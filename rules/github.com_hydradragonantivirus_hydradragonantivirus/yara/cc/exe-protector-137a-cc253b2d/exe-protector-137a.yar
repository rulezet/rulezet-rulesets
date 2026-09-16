import "pe"
rule _EXE_Protector_137a_
{
	meta:
		description = "EXE Protector 1.37a"
	strings:
		$0 = {68 54 14 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 5C C3 4D EA 29 A6 D2 11 BB FF 44 45 53 54 00 00 00 00 00 00 00 00 01 00 00 00 00 00 B5 09 00 A0 70 72 66 45 6D 62 65 64 64 65 64 43 6F 64 65}
	condition:
		$0 at pe.entry_point
}