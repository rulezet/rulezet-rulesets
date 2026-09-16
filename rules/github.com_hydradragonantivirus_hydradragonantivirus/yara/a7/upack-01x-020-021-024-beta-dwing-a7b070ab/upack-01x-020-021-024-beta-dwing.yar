import "pe"
rule _Upack_01x__020__021__024_beta__Dwing_
{
	meta:
		description = "Upack 0.1x / 0.20 / 0.21 / 0.24 beta -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33}
		$1 = {BE 88 01 40 00 AD 8B F8}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}