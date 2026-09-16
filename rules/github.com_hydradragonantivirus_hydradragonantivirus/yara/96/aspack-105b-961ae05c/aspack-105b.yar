import "pe"
rule _ASPack_105b_
{
	meta:
		description = "ASPack 1.05b"
	strings:
		$0 = {75 00 E9}
	condition:
		$0 at pe.entry_point
}