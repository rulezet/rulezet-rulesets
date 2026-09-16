import "pe"
rule _VMProtect_1704_phpbb3_
{
	meta:
		description = "VMProtect 1.70.4-> phpbb3"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}