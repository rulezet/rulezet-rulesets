import "pe"
rule _eXPressor_11__CGSoftLabs_
{
	meta:
		description = "eXPressor 1.1 -> CGSoftLabs"
	strings:
		$0 = {E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}