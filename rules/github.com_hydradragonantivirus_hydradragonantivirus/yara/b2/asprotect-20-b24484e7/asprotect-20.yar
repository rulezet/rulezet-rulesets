import "pe"
rule _ASProtect_20_
{
	meta:
		description = "ASProtect 2.0"
	strings:
		$0 = {68 01 ?? 40 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at pe.entry_point
}