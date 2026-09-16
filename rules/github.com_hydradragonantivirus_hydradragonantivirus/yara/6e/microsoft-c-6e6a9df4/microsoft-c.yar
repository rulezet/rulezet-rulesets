import "pe"
rule _Microsoft_C_
{
	meta:
		description = "Microsoft C"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? B8}
	condition:
		$0 at pe.entry_point
}