import "pe"
rule _PKLITE_v114_v115_v120_3_
{
	meta:
		description = "PKLITE v1.14, v1.15, v1.20 (3)"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F}
	condition:
		$0 at pe.entry_point
}