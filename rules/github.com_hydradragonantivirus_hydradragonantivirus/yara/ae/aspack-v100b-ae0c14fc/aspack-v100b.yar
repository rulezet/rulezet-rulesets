import "pe"
rule _ASPack_v100b_
{
	meta:
		description = "ASPack v1.00b"
	strings:
		$0 = {60 E8 5D 81 ED D2 2A 44 B8 CC 2A 44 03 C5 2B 85 A5 2E 44 89 85 B1 2E 44 80 BD 9C 2E}
	condition:
		$0 at pe.entry_point
}