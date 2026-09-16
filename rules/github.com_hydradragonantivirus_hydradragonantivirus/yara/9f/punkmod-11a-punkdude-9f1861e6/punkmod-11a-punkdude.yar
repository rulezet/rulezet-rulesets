import "pe"
rule _PuNkMoD_11a__PuNkDuDe_
{
	meta:
		description = "PuNkMoD 1.1a -> PuNkDuDe"
	strings:
		$0 = {94 B9 5E 01 00 00 BC ?? ?? ?? 00 80 34 0C ?? 80 2C 0C ?? D2}
	condition:
		$0 at pe.entry_point
}