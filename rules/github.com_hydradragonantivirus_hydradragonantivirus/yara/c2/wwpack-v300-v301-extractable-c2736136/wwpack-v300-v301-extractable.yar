import "pe"
rule _WWPACK_v300_v301_Extractable_
{
	meta:
		description = "WWPACK v3.00, v3.01 (Extractable)"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC}
	condition:
		$0 at pe.entry_point
}