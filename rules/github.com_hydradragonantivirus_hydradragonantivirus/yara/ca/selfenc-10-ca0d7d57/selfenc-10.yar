import "pe"
rule _SelfEnc_10_
{
	meta:
		description = "SelfEnc 1.0"
	strings:
		$0 = {BB 0F 01 B9 8F 18 33 C0 2E 80 2F 00 43 E2 F9}
	condition:
		$0 at pe.entry_point
}