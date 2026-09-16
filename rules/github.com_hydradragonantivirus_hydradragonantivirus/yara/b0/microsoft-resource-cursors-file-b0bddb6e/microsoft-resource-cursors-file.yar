import "pe"
rule _Microsoft_Resource_Cursors_file_
{
	meta:
		description = "Microsoft Resource Cursors file"
	strings:
		$0 = {00 00 02 00 01 00 20 20 00 00 ?? 00 ?? 00 E8 02 00 00 16}
	condition:
		$0 at pe.entry_point
}