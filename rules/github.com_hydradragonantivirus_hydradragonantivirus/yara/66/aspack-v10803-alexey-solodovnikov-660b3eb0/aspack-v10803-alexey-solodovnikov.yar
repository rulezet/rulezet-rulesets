import "pe"
rule _ASPack_v10803__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.08.03 -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD}
		$1 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E}
		$2 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD}
		$3 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point or $3 at pe.entry_point
}