import "pe"
rule _modified_HACKSTOP_v111f_
{
	meta:
		description = "modified HACKSTOP v1.11f"
	strings:
		$0 = {52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8}
	condition:
		$0 at pe.entry_point
}