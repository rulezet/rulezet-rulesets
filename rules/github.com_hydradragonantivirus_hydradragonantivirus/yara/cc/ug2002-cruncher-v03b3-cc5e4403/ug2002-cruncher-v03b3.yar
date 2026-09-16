import "pe"
rule _UG2002_Cruncher_v03b3_
{
	meta:
		description = "UG2002 Cruncher v0.3b3"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 8D B0 D8 01 83 CD FF 31 DB 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB}
	condition:
		$0 at pe.entry_point
}