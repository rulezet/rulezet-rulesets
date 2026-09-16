import "pe"
rule _PESHiELD_025__ANAKiN_DaVinci_
{
	meta:
		description = "PESHiELD 0.25 -> ANAKiN [DaVinci"
	strings:
		$0 = {60 E8 2B 00 00 00}
	condition:
		$0 at pe.entry_point
}