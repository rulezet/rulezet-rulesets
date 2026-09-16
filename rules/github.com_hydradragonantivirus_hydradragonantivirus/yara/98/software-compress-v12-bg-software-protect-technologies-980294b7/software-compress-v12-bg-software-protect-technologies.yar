import "pe"
rule _Software_Compress__V12___BG_Software_Protect_Technologies_
{
	meta:
		description = "Software Compress  V1.2 ->  BG Software Protect Technologies"
	strings:
		$0 = {E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00}
	condition:
		$0 at pe.entry_point
}