import "pe"
rule _TAV_
{
	meta:
		description = "TAV"
	strings:
		$0 = {E8 ?? ?? 4D 5A CB}
	condition:
		$0 at pe.entry_point
}