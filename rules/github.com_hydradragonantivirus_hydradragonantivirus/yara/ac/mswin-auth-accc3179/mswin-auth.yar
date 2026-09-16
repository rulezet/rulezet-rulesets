rule mswin_auth {
	meta:
		description = "Chinese Hacktool Set - file mswin_auth.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "512cbd02f6fe69482e005a067db4eb07ce62d5a0"
	strings:
		$s1 = "No such user or wrong password" fullword ascii
		$s2 = "%s [-A|D UserGroup][-O DefaultDomain][-d]" fullword ascii
		$s3 = "mswin_auth[%d]: " fullword ascii
		$s4 = "Unknown option: -%c. Exiting" fullword ascii
		$s5 = "-D can specify a Windows Local Group name not allowed to authenticate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}