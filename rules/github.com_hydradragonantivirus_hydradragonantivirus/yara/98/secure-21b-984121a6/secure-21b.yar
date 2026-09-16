import "pe"
rule _Secure_21b_
{
	meta:
		description = "Secure 2.1b"
	strings:
		$0 = {8C C8 05 00 00 50 B8 90 01 50 CB 00}
	condition:
		$0 at pe.entry_point
}