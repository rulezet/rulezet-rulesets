import "pe"
rule _EXE__yy66_
{
	meta:
		description = "EXE -> yy66"
	strings:
		$0 = {68 78 18 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30}
	condition:
		$0 at pe.entry_point
}