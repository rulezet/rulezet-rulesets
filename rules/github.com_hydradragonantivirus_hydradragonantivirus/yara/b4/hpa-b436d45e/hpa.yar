import "pe"
rule _HPA_
{
	meta:
		description = "HPA"
	strings:
		$0 = {E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3}
	condition:
		$0 at pe.entry_point
}