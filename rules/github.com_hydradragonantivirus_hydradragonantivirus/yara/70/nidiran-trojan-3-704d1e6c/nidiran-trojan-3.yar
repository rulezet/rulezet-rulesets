rule Nidiran_Trojan_3 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
	strings:
		$s1 = "WriteProcessMemory fail at %d " fullword ascii
		$s2 = "CreateRemoteThread fail at %d " fullword ascii
		$s3 = "VirtualAllocEx fail at %d " fullword ascii
		$s4 = "CreateRemoteThread Succ" fullword ascii
		$s5 = "VirtualAllocEx succ" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 3 of ($s*) ) or ( all of them )
}