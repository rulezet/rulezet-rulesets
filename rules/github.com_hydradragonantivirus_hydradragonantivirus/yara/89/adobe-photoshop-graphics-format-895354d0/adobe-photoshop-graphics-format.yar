import "pe"
rule _Adobe_PhotoShop_Graphics_format_
{
	meta:
		description = "Adobe PhotoShop Graphics format"
	strings:
		$0 = {38 42 50 53 00 01 00 00}
	condition:
		$0 at pe.entry_point
}