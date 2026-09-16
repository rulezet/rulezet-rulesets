import "pe"
rule _Packman_0001_
{
	meta:
		description = "Packman 0.0.0.1"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 8D A8}
	condition:
		$0 at pe.entry_point
}