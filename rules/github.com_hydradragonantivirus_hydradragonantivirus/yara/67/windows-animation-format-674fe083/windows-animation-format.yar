import "pe"
rule _Windows_Animation_format_
{
	meta:
		description = "Windows Animation format"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E 4C 49 53 54}
	condition:
		$0 at pe.entry_point
}