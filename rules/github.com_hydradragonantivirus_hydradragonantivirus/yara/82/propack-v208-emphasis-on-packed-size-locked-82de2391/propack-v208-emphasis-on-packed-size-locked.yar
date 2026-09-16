import "pe"
rule _PROPACK_v208_emphasis_on_packed_size_locked_
{
	meta:
		description = "PRO-PACK v2.08, emphasis on packed size, locked"
	strings:
		$0 = {83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B}
	condition:
		$0 at pe.entry_point
}