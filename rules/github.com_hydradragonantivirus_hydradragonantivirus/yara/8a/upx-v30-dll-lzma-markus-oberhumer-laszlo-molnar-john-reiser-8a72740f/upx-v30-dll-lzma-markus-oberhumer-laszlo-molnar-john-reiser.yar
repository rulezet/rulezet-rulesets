import "pe"
rule _UPX_v30_DLL_LZMA__Markus_Oberhumer__Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX v3.0 (DLL_LZMA) -> Markus Oberhumer & Laszlo Molnar & John Reiser"
	strings:
		$0 = {80 7C 24 08 01 0F 85 C7 0B 00 00 60 BE 00 ?? ?? ?? 8D BE 00 ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}