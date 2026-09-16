import "pe"
rule _eXPressor_13__CGSoftLabs_
{
	meta:
		description = "eXPressor 1.3 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E}
	condition:
		$0 at pe.entry_point
}