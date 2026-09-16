rule Nidiran_Trojan_2 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "eaee2bf83cf90d35dab8a4711f7a5f2ebf9741007668f3746995f4564046fbdf"
	strings:
		$s1 = "%userprofile%\\Security Center\\secriter.dll" fullword ascii
		$s2 = "WorkDll.dll" fullword ascii
		$s3 = "InstallUserProcess is called" fullword ascii
		$s4 = "DLL_PROCESS_ATTACH is called" fullword ascii
		$s5 = "CreateRemoteThread Succ" fullword ascii
		$s6 = "DoRunRemote" fullword ascii
		$s7 = "DllRegisterServer is called" fullword ascii
		$s8 = "DoInstallEntry is called" fullword ascii
		$s9 = "copy Fail" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 5 of ($s*) ) or ( all of them )
}