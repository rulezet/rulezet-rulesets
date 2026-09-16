import "pe"
rule _SuckStop_v111_
{
	meta:
		description = "SuckStop v1.11"
	strings:
		$0 = {EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B}
	condition:
		$0 at pe.entry_point
}