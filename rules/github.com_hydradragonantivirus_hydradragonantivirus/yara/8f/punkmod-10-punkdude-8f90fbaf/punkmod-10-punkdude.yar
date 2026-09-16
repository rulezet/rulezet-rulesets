import "pe"
rule _PuNkMoD_10__PuNkDuDe_
{
	meta:
		description = "PuNkMoD 1.0 -> PuNkDuDe"
	strings:
		$0 = {94 B9 60 01 00 00 BC ?? ?? 40 00 80 34 0C ?? E2 FA EB DF}
	condition:
		$0 at pe.entry_point
}