import "pe"
rule _Vx_MTE_nonencrypted_
{
	meta:
		description = "Vx: MTE (non-encrypted)"
	strings:
		$0 = {F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48}
	condition:
		$0 at pe.entry_point
}