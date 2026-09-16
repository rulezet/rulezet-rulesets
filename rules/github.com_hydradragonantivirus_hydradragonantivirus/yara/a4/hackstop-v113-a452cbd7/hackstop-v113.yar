import "pe"
rule _HACKSTOP_v113_
{
	meta:
		description = "HACKSTOP v1.13"
	strings:
		$0 = {52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA}
	condition:
		$0 at pe.entry_point
}