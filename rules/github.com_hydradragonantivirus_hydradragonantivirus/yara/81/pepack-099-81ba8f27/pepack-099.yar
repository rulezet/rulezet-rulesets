import "pe"
rule _PEPACK_099_
{
	meta:
		description = "PE-PACK 0.99"
	strings:
		$0 = {60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2}
	condition:
		$0 at pe.entry_point
}