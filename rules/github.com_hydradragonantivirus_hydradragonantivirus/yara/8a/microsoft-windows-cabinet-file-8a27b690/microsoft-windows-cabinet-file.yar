import "pe"
rule _Microsoft_Windows_Cabinet_file_
{
	meta:
		description = "Microsoft Windows Cabinet file"
	strings:
		$0 = {4D 53 43 46}
	condition:
		$0 at pe.entry_point
}