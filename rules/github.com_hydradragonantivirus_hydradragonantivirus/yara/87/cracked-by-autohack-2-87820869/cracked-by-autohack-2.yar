import "pe"
rule _Cracked_by_Autohack_2_
{
	meta:
		description = "Cracked by Autohack (2)"
	strings:
		$0 = {0E 1F B4 09 BA ?? ?? CD 21 FA 8E 06 ?? ?? BE ?? ?? 8B 0E ?? ?? 83 F9}
	condition:
		$0 at pe.entry_point
}