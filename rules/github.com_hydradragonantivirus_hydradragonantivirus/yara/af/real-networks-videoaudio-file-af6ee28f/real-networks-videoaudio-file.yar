import "pe"
rule _Real_Networks_VideoAudio_file_
{
	meta:
		description = "Real Networks Video/Audio file"
	strings:
		$0 = {2E 52 4D 46}
	condition:
		$0 at pe.entry_point
}