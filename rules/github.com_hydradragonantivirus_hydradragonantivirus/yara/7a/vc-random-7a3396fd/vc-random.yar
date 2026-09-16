rule VC_Random {
	meta:
		author = "_pusher_"
		description = "Look for VC Random function"
		date = "2016-10"
		version = "0.2"
	strings:
		$c0 = { E8 ?? ?? ?? ?? 8B 48 14 69 C9 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 8B C1 C1 E8 10 25 FF 7F 00 00 C3 }
		$c1 = { E8 ?? ?? ?? ?? 69 48 14 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 C1 E9 10 81 E1 FF 7F 00 00 8B C1 C3 }
		$c2 = { A1 ?? ?? ?? ?? 69 C0 FD 43 03 00 05 C3 9E 26 00 A3 ?? ?? ?? ?? C1 F8 10 25 FF 7F 00 00 C3 }
	condition:
		any of ($c*)
}