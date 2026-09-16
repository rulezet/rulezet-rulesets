rule RoguePCDefender
{
	meta:
		Description  = "Rogue.FakeDef.rc"
		ThreatLevel  = "5"
		
	strings:
		$hex0 = { 8A 4A 01 56 57 33 FF 47 8B C7 8D 72 03 85 C0 74 28 80 C1 0B 80 F9 5A 7E 11 0F BE C1 83 E8 41 6A 19 99 59 F7 F9 80 C2 41 8A CA 33 C0 38 0E 0F 94 C0 47 46 46 83 FF 10 7C D4 5F 5E C3 }
		
	condition:
		any of ($hex*)
}