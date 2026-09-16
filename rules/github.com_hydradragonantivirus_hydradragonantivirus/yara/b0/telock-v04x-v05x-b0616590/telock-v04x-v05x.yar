import "pe"
rule _tElock_v04x__v05x_
{
	meta:
		description = "tElock v0.4x - v0.5x"
	strings:
		$0 = {E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0}
	condition:
		$0 at pe.entry_point
}