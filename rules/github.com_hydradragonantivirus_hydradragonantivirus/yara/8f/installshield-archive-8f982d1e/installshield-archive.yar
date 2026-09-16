import "pe"
rule _InstallShield_Archive_
{
	meta:
		description = "InstallShield Archive"
	strings:
		$0 = {2A AB 79 D8}
	condition:
		$0 at pe.entry_point
}