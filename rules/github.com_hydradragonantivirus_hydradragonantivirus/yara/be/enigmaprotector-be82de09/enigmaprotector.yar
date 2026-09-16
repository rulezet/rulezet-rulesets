import "pe"
rule EnigmaProtector : Vladmir Sukhov
{
	meta:
		author="_pusher_"
		date = "2016-08"
		
	strings:
		$a0 = "ENIGMA" ascii
		$aa1 = { 60 E8 00 00 00 00 5D 81 ED ?? 00 00 00 81 ED ?? ?? ?? 00 E9 ?? 00 00 00 }
		$aa2 = { C8 63 78 4F 45 53 50 16 24 F6 78 F2 F7 0A 6E 85 51 5A 0F 26 52 55 24 93 29 18 90 3A F4 FB E6 43 53 1B 52 01 98 00 60 E8 00 00 00 00 5D 83 C5 FA 81 ED }
		$aa3 = { DE 4C A4 EE 26 40 68 60 3E B4 B8 E9 07 A8 F8 FD C7 9C 38 C1 8E A9 9E 48 AA 4A 9F E7 00 00 00 EB 08 00 0C 03 00 00 00 00 00 60 E8 00 00 00 00 5D 81 ED }
	
		$bb0 = "virtualboxemulunit" wide ascii nocase
		$bb1 = "virtualboximportunit" wide ascii nocase
		$bb2 = "virtualboxunit" wide ascii nocase
		$bb3 = "enigma_keygen_routines" wide ascii nocase
		$bb4 = "virtualboxdatabase" wide ascii nocase
		$bb5 = "virtualboxdisasm" wide ascii nocase
		$bb6 = "StringHashUnit" wide ascii nocase
		$bb7 = "virtualboxglobalsunit" wide ascii nocase
		$bb8 = "VirtualBoxGlobals" wide ascii nocase
	condition:
				($a0 at (pe.entry_point+0x18)) or (any of ($aa*) ) or 5 of ($bb*)

}