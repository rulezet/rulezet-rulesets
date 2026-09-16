import "pe"
rule _Inbuild_v10_hard_
{
	meta:
		description = "Inbuild v1.0 [hard]"
	strings:
		$0 = {B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2}
	condition:
		$0 at pe.entry_point
}