import "pe"
rule _ASPack_v10801__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.08.01 -> Alexey Solodovnikov"
	strings:
		$0 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D}
		$1 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D}
		$2 = {60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}