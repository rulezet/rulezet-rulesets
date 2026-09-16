import "pe"
rule _AVI_movie_file_
{
	meta:
		description = "AVI movie file"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 41 56 49 ?? 4C 49 53 54}
	condition:
		$0 at pe.entry_point
}