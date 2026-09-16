import "pe"
rule _Encrypted_by_RSCC286_v102_
{
	meta:
		description = "Encrypted by: RSCC/286 v1.02"
	strings:
		$0 = {FE 52 53 43 43 2F 31 2E 30 32 FE}
	condition:
		$0 at pe.entry_point
}