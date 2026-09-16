import "pe"
rule _SWAG_Archive_
{
	meta:
		description = "SWAG Archive"
	strings:
		$0 = {2D 73 77 31 2D}
	condition:
		$0 at pe.entry_point
}