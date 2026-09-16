import "pe"
rule _GIF89a_Graphics_format_
{
	meta:
		description = "GIF89a Graphics format"
	strings:
		$0 = {47 49 46 38 39 61}
	condition:
		$0 at pe.entry_point
}