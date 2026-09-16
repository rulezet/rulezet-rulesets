import "pe"
rule _PeX_099__bartCrackPl_
{
	meta:
		description = "PeX 0.99 -> bart^CrackPl"
	strings:
		$0 = {E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at pe.entry_point
}