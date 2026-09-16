import "pe"
rule _SCRAM_v08a1_
{
	meta:
		description = "SCRAM! v0.8a1"
	strings:
		$0 = {B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C}
	condition:
		$0 at pe.entry_point
}