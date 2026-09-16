import "pe"
rule _XCF_File_Format_by_Adeline_Software_
{
	meta:
		description = "XCF File Format by Adeline Software"
	strings:
		$0 = {46 72 61 6D 65 4C 65 6E F4 0F}
	condition:
		$0 at pe.entry_point
}