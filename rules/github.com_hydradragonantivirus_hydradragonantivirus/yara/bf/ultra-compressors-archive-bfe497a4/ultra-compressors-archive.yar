import "pe"
rule _Ultra_Compressors_Archive_
{
	meta:
		description = "Ultra Compressor`s Archive"
	strings:
		$0 = {55 43 32 1A}
	condition:
		$0 at pe.entry_point
}