import "pe"
rule _FileShield_
{
	meta:
		description = "FileShield"
	strings:
		$0 = {50 1E EB ?? 90 00 00 8B D8}
	condition:
		$0 at pe.entry_point
}