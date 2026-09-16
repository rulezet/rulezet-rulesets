import "pe"
rule _unknown_by_Woody_
{
	meta:
		description = "unknown by Woody"
	strings:
		$0 = {B8 B9 0F 8E D8 8C 1E 04 00 8C 1E 08 00 8C C8 A3 00 00 E9 54 36}
	condition:
		$0 at pe.entry_point
}