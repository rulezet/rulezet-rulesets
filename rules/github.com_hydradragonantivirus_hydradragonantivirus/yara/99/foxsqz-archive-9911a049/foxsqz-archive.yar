import "pe"
rule _FOXSQZ_Archive_
{
	meta:
		description = "FOXSQZ Archive"
	strings:
		$0 = {46 4F 58 53 51 5A}
	condition:
		$0 at pe.entry_point
}