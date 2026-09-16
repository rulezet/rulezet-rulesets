import "pe"
rule _Themida_v2010__v2065_or_newer_
{
	meta:
		description = "Themida v2.0.1.0 - v2.0.6.5 (or newer)"
	strings:
		$0 = {83 EC 04 50 53 E8 ?? 00 00 00 CC 58 8B D8 40 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68}
	condition:
		$0 at pe.entry_point
}