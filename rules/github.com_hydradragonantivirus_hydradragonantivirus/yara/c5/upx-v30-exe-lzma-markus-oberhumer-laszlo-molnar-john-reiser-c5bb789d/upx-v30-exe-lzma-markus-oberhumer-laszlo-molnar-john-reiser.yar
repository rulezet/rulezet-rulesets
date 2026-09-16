import "pe"
rule _UPX_v30_EXE_LZMA__Markus_Oberhumer__Laszlo_Molnar__John_Reiser_
{
	meta:
		description = "UPX v3.0 (EXE_LZMA) -> Markus Oberhumer & Laszlo Molnar & John Reiser"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 57 83 C3 04 53 68 ?? ?? ?? 00 56}
	condition:
		$0 at pe.entry_point
}