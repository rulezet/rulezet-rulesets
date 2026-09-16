import "pe"
rule _ASPack_v102b__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.02b -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}