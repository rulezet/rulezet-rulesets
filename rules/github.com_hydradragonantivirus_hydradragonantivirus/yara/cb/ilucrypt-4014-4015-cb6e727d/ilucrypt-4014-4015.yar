import "pe"
rule _iLUCRYPT_4014__4015_
{
	meta:
		description = "iLUCRYPT 4.014 - 4.015"
	strings:
		$0 = {8B EC FA C7 46 F7 00 00 42 81 FA 00 00 75 F9 FF 66 F7}
	condition:
		$0 at pe.entry_point
}