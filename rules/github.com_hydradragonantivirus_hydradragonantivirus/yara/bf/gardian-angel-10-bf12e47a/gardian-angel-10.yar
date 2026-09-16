import "pe"
rule _Gardian_Angel_10_
{
	meta:
		description = "Gardian Angel 1.0"
	strings:
		$0 = {06 8C C8 8E D8 8E C0 FC BF ?? ?? EB}
	condition:
		$0 at pe.entry_point
}