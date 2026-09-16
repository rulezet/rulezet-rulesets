import "pe"
rule _ASPack_v10803_
{
	meta:
		description = "ASPack v1.08.03"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 DD 2B 9D B1 50 44 ?? 83 BD AC 50 44 ?? ?? 89 9D BB}
		$2 = {60 E8 41 06 ?? ?? EB}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}