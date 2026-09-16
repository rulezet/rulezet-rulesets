import "pe"
rule _File_Analyzer_Registration_file_v11_
{
	meta:
		description = "File Analyzer Registration file v1.1"
	strings:
		$0 = {24 46 41 52 45 47 24 45 4E 43 3D ?? 26 26 52 45 47 3D ?? 26 26 45 58 50 3D}
	condition:
		$0 at pe.entry_point
}