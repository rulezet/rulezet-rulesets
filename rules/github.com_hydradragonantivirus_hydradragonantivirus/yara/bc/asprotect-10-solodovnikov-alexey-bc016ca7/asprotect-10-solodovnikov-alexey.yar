import "pe"
rule _ASProtect_10__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.0 -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 01 00 00 00 90 5D 81 ED ?? ?? ?? 00 BB ?? ?? ?? 00 03 DD 2B 9D}
	condition:
		$0 at pe.entry_point
}