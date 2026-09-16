import "pe"
rule _XM_music_file_
{
	meta:
		description = "XM music file"
	strings:
		$0 = {45 78 74 65 6E 64 65 64 20 4D 6F 64 75 6C 65 3A}
	condition:
		$0 at pe.entry_point
}