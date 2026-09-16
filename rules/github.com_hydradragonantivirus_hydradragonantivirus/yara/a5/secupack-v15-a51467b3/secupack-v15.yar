import "pe"
rule _SecuPack_v15_
{
	meta:
		description = "SecuPack v1.5"
	strings:
		$0 = {60 B8 B8 8A 14 08 80 F2 88 14 08 41 83 F9 75}
	condition:
		$0 at pe.entry_point
}