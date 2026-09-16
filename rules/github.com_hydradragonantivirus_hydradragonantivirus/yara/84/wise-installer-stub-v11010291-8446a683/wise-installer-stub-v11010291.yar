import "pe"
rule _Wise_Installer_Stub_v11010291_
{
	meta:
		description = "Wise Installer Stub v1.10.1029.1"
	strings:
		$0 = {53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33}
	condition:
		$0 at pe.entry_point
}