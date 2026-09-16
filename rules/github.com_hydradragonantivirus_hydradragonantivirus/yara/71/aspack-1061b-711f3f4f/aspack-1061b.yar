import "pe"
rule _ASPAck_1061b_
{
	meta:
		description = "ASPAck 1.061b"
	strings:
		$0 = {90 90 75 00 E9}
	condition:
		$0 at pe.entry_point
}