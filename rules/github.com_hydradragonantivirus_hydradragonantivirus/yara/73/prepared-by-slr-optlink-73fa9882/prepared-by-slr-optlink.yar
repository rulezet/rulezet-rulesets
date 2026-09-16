import "pe"
rule _Prepared_by_SLR_OPTLINK_
{
	meta:
		description = "Prepared by SLR (OPTLINK)"
	strings:
		$0 = {87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 ?? ?? 16 07 0E 1F}
	condition:
		$0 at pe.entry_point
}