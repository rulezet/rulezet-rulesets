import "pe"
rule _PCShrinker_v045__Virogen_
{
	meta:
		description = "PC-Shrinker v0.45 -> Virogen"
	strings:
		$0 = {BD 01 AD E3 38 40 00 FF B5 DF 38 40}
	condition:
		$0 at pe.entry_point
}