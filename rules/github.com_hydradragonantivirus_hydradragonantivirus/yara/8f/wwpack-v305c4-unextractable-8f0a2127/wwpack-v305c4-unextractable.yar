import "pe"
rule _WWPACK_v305c4_Unextractable_
{
	meta:
		description = "WWPACK v3.05c4 (Unextractable)"
	strings:
		$0 = {03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at pe.entry_point
}