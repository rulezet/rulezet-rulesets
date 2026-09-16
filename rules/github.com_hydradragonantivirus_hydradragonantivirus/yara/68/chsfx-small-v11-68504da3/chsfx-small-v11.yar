import "pe"
rule _ChSfx_small_v11_
{
	meta:
		description = "ChSfx (small) v1.1"
	strings:
		$0 = {BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89}
	condition:
		$0 at pe.entry_point
}