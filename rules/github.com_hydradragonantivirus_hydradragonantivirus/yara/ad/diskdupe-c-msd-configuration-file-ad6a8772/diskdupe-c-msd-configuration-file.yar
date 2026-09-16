import "pe"
rule _DiskDupe_c_MSD_Configuration_file_
{
	meta:
		description = "DiskDupe (c) MSD Configuration file"
	strings:
		$0 = {4D 53 44 20 44 61 74 61 20 56 65 72 73}
	condition:
		$0 at pe.entry_point
}