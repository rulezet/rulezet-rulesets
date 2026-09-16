import "pe"
rule _NoobyProtect_SE_Public_V1110__Nooby___20081228_
{
	meta:
		description = "NoobyProtect SE Public V1.1.1.0 -> Nooby  * 20081228"
	strings:
		$0 = {E9 18 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 31 2E 31 2E 30 00}
	condition:
		$0 at pe.entry_point
}