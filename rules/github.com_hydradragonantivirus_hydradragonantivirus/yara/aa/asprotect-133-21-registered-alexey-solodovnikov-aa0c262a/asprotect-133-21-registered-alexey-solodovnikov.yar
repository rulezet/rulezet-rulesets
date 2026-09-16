import "pe"
rule _ASProtect_133__21_Registered__Alexey_Solodovnikov_
{
	meta:
		description = "ASProtect 1.33 - 2.1 Registered -> Alexey Solodovnikov"
	strings:
		$0 = {68 01 ?? ?? ?? E8 01 00 00 00 C3 C3}
	condition:
		$0 at pe.entry_point
}