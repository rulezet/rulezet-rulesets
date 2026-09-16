import "pe"
rule _Microsoft_Windows_Help_file_
{
	meta:
		description = "Microsoft Windows Help file"
	strings:
		$0 = {3F 5F 03}
	condition:
		$0 at pe.entry_point
}