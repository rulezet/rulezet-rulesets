import "pe"
rule _XCOM_100_
{
	meta:
		description = "XCOM 1.00"
	strings:
		$0 = {43 42 47 BA 1E 01 B8 B4 4C 87 E5 BC 15 01 EB 02 F5 EA 50 B4 09 CD 21 87 E5 33 ED E8}
	condition:
		$0 at pe.entry_point
}