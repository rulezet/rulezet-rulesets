import "pe"
rule _Goldeds_Output_text_file_
{
	meta:
		description = "Golded's Output text file"
	strings:
		$0 = {C4 20 5B}
	condition:
		$0 at pe.entry_point
}