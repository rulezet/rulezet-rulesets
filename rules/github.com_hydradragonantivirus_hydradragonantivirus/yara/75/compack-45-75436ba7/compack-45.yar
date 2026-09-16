import "pe"
rule _COMPACK_45_
{
	meta:
		description = "COMPACK 4.5"
	strings:
		$0 = {BE 00 00 E8 00 00 5D 83 C5 FA 55 50 53 51 52 0E 07 0E 1F 8B CE 8D 72 42 BF 82 FF D1 E9 FD 57 F3 A5 8D 75 02 FC F9 8B FD C3}
	condition:
		$0 at pe.entry_point
}