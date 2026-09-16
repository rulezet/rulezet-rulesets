import "pe"
rule _PKLITE32_v11_
{
	meta:
		description = "PKLITE32 v1.1"
	strings:
		$0 = {68 68 68 ?? ?? ?? ??}
		$1 = {50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20}
		$2 = {53 E8 ?? ?? ?? ?? 5B 8B C3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}