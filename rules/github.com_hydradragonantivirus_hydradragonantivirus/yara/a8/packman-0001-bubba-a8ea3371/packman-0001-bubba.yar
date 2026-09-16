import "pe"
rule _Packman_0001__bubba_
{
	meta:
		description = "Packman 0.0.0.1 -> bubba"
	strings:
		$0 = {60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00}
	condition:
		$0 at pe.entry_point
}