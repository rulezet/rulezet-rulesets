import "pe"
rule _Amiga_AIFF_8SFX_Audio_file_
{
	meta:
		description = "Amiga AIFF 8SFX Audio file"
	strings:
		$0 = {46 4F 52 4D ?? ?? ?? ?? 38 53 56 58 56 48 44 52}
	condition:
		$0 at pe.entry_point
}