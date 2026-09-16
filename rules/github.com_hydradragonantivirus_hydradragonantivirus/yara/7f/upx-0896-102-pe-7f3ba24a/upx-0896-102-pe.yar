import "pe"
rule _UPX_0896__102_PE_
{
	meta:
		description = "UPX 0.89.6 - 1.02 [PE]"
	strings:
		$0 = {60 BE 00 00 00 00 8D BE 00 00 00 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8}
	condition:
		$0 at pe.entry_point
}