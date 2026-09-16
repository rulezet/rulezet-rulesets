rule CN_Honker__mysql_injectV1_1_Creak_DomainBlastingTool_super_Injection1 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files mysql_injectV1.1_Creak.exe, DomainBlastingTool.exe, super Injection1.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "a1f066789f48a76023598c5777752c15f91b76b0"
		hash1 = "6fb6b9d8eb15da3ceabb8cc030eb1bf0fe743485"
		hash2 = "8ff2df40c461f6c42b92b86095296187f2b59b14"
	strings:
		$s1 = "Dark Teal" fullword wide
		$s2 = "TRzFrameControllerProperty" fullword ascii
		$s3 = "hkeyLocalMachine" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}