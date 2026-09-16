import "pe"
rule _PowerBASICCC_30x_
{
	meta:
		description = "PowerBASIC/CC 3.0x"
	strings:
		$0 = {55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85}
	condition:
		$0 at pe.entry_point
}