import "pe"
rule _Vx_VCL_encrypted_
{
	meta:
		description = "Vx: VCL (encrypted)"
	strings:
		$0 = {01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3}
		$1 = {01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}