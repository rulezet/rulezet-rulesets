import "pe"
rule _DiskDupe_c_MSD_Users_file_
{
	meta:
		description = "DiskDupe (c) MSD Users file"
	strings:
		$0 = {4D 53 44 20 55 73 65 72 73 20 56 65 72 73 69 6F 6E}
	condition:
		$0 at pe.entry_point
}