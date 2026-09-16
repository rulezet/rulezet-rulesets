import "pe"
rule _PESHiELD_02_
{
	meta:
		description = "PE-SHiELD 0.2"
	strings:
		$0 = {60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04}
	condition:
		$0 at pe.entry_point
}