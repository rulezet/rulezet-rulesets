import "pe"
rule _HACKSTOP_v113__DarkStop_v10_
{
	meta:
		description = "HACKSTOP v1.13 / DarkStop v1.0"
	strings:
		$0 = {FA BD ?? ?? D4 85 4E 32 EB EB}
	condition:
		$0 at pe.entry_point
}