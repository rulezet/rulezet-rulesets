import "pe"
rule _First_Publisher_Graphics_format_
{
	meta:
		description = "First Publisher Graphics format"
	strings:
		$0 = {00 00 ?? 01 00 00 ?? 02}
		$1 = {00 00 ?? 00 00 00 ?? 01}
	condition:
		$0 at pe.entry_point or $1
}