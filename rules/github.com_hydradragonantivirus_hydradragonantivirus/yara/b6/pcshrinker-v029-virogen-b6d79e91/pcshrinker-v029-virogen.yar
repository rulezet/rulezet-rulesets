import "pe"
rule _PCShrinker_v029__Virogen_
{
	meta:
		description = "PC-Shrinker v0.29 -> Virogen"
	strings:
		$0 = {BD ?? ?? ?? ?? 01 AD 55 39 40 00 8D B5 35 39 40}
	condition:
		$0 at pe.entry_point
}