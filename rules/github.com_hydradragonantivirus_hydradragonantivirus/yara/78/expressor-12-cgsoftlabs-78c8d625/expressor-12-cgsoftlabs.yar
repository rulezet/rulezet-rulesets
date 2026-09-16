import "pe"
rule _eXPressor_12__CGSoftLabs_
{
	meta:
		description = "eXPressor 1.2 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E}
	condition:
		$0 at pe.entry_point
}