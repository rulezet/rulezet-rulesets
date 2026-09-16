import "pe"
rule _SND_music_file_
{
	meta:
		description = "SND music file"
	strings:
		$0 = {00 00 F8 2A ?? 00}
	condition:
		$0 at pe.entry_point
}