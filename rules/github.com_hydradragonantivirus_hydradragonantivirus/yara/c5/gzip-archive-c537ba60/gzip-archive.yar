import "pe"
rule _GZIP_Archive_
{
	meta:
		description = "GZIP Archive"
	strings:
		$0 = {1F 8B 08 08 ?? ?? ?? 35}
	condition:
		$0 at pe.entry_point
}