import "pe"
rule _JAM_v211_
{
	meta:
		description = "JAM v2.11"
	strings:
		$0 = {50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB}
	condition:
		$0 at pe.entry_point
}