import "pe"
rule _Windows_Group_file_
{
	meta:
		description = "Windows Group file"
	strings:
		$0 = {50 4D 43 43}
	condition:
		$0 at pe.entry_point
}