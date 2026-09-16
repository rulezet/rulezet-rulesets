import "pe"
rule _OS2_Icon_Graphics_format_
{
	meta:
		description = "OS/2 Icon Graphics format"
	strings:
		$0 = {43 49 4E 00 00 00}
	condition:
		$0 at pe.entry_point
}