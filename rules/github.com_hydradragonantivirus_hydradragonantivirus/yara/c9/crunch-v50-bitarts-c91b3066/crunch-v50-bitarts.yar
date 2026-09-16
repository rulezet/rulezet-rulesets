import "pe"
rule _Crunch_V50__Bitarts_
{
	meta:
		description = "Crunch V5.0 -> Bitarts"
	strings:
		$0 = {03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
		$1 = {EB 15 03 00 00 00 06}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}