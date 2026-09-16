import "pe"
rule _Aluwain_v809_
{
	meta:
		description = "Aluwain v8.09"
	strings:
		$0 = {8B EC 1E E8 ?? ?? 9D 5E}
	condition:
		$0 at pe.entry_point
}