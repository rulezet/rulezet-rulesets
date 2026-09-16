import "pe"
rule _ASPack_v100b__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.00b -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44}
	condition:
		$0 at pe.entry_point
}