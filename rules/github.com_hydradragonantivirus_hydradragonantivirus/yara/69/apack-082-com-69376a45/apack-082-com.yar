import "pe"
rule _aPack_082_COM_
{
	meta:
		description = "aPack 0.82 [COM]"
	strings:
		$0 = {8C C8 80 C4 10 8E C0 FC B9 00 00 BE 00 01 8B FE 57 F3 A5 5F BE BC 01 06 68 20 01 1E 07 8E D8 CB 06 57 B6 01 BD 89 01 FF D5 73 5B FF D5 73 1C FF D5 73 3D BB A0 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 B1 01 85 DB 75 34 93 EB 36 E8 46 00 49 49}
	condition:
		$0 at pe.entry_point
}