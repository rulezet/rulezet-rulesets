import "pe"
rule _RAR_SFX_
{
	meta:
		description = "RAR SFX"
	strings:
		$0 = {E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 00 00 00 00 90}
		$1 = {80 3A 52 75 2D 80 7A 01 61 75 27 80 7A 02 72 75 21 80 7A 03 21 75 1B 80 7A 04 1A 75 15 80 7A 05 07 75 0F 80 7A 06 00 75 09}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}