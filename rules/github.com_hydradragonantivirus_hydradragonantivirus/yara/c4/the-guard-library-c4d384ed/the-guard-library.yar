import "pe"
rule _The_Guard_Library_
{
	meta:
		description = "The Guard Library"
	strings:
		$0 = {B8 EF BE AD DE 50 6A FF 15 10 19 40 E9 AD FF FF}
	condition:
		$0 at pe.entry_point
}