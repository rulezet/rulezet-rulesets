import "pe"
rule _S3M_music_file_
{
	meta:
		description = "S3M music file"
	strings:
		$0 = {53 43 52 4D}
	condition:
		$0 at pe.entry_point
}