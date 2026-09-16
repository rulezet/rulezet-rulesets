import "pe"
rule _UPX_070_PE_
{
	meta:
		description = "UPX 0.70 [PE]"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 66 81 87 00 00 00 00 00 00 8D B0 EC 01 00 00 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	condition:
		$0 at pe.entry_point
}