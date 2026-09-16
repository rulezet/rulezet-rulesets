import "pe"
rule _Creative_Audio_file_
{
	meta:
		description = "Creative Audio file"
	strings:
		$0 = {43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 69 6C 65}
	condition:
		$0 at pe.entry_point
}