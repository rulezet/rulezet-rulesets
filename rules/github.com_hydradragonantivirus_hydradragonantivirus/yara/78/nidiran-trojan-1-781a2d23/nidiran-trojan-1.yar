rule Nidiran_Trojan_1 {
	meta:
		description = "Detects Nidiran malware from Suckfly APT group"
		author = "Florian Roth"
		reference = "http://goo.gl/F3r1rr"
		date = "2016-06-08"
		hash1 = "47731c9d985ebc2bd7227fced3cc44c6d72e29b52f76fccbdaddd76cc3450706"
		hash2 = "c2022e1114b162e79e44d974fd310d53e1bbdd8cb4f217553c1227cafed78855"
	strings:
		$x1 = "RUN SHELLCODE FAIL" fullword ascii
		$x2 = "RUN DLLMEM THREAD FAIL" fullword ascii

		$s1 = "cmd.exe /c %s" fullword ascii
		$s2 = "CreateProcess returned %d, error at %d" fullword ascii
		$s3 = "RUN PROCESS FAILD!" fullword ascii
		$s5 = "RUN PROCESS SUCC!" fullword ascii
		$s6 = "error to create pipe!" fullword ascii
		$s7 = "5308.tmp" fullword ascii
		$s8 = "MODIFYCONFIG FAIL!" fullword ascii
		$s9 = "%s\\%08x.exe" fullword ascii
		$s10 = "GetFileAttributes FILE FAILD" fullword ascii
		$s11 = "DOWNLOAD FILE FAILD" fullword ascii
		$s12 = "MODIFYCONFIG SUCC!" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 10 of them )
}