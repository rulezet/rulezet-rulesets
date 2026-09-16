import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Cue_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Cue)"
	strings:
		$0 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB}
	condition:
		$0 at pe.entry_point
}