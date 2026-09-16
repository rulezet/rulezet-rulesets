import "pe"
rule _PELOCknt_201_
{
	meta:
		description = "PELOCknt 2.01"
	strings:
		$0 = {EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD 20 EB 60 EB 03 CD 20 03 E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 04 CD EB 03 CD EB 02 CD 20 EB 03 CD 20 EA FC EB 03 CD 20 69 E8 00 00 00 00 EB 02 EB 01 EB 01 EB 5E EB 03 CD 20 EB EB}
	condition:
		$0 at pe.entry_point
}