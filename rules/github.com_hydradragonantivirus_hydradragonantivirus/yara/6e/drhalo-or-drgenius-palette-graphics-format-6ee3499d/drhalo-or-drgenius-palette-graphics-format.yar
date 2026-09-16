import "pe"
rule _DrHalo_or_DrGenius_Palette_Graphics_format_
{
	meta:
		description = "DrHalo or DrGenius Palette Graphics format"
	strings:
		$0 = {41 48 E3 00 00 00 0A 00}
	condition:
		$0 at pe.entry_point
}