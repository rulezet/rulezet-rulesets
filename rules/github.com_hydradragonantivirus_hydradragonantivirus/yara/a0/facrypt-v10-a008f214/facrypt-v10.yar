import "pe"
rule _FACRYPT_v10_
{
	meta:
		description = "FACRYPT v1.0"
	strings:
		$0 = {B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3}
	condition:
		$0 at pe.entry_point
}