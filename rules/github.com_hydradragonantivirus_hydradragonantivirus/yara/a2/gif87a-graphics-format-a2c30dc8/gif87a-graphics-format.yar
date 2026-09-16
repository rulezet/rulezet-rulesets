import "pe"
rule _GIF87a_Graphics_format_
{
	meta:
		description = "GIF87a Graphics format"
	strings:
		$0 = {47 49 46 38 37 61}
	condition:
		$0 at pe.entry_point
}