import "pe"
rule _NoobyProtect_1x__Nooby_
{
	meta:
		description = "NoobyProtect 1.x -> Nooby"
	strings:
		$0 = {18 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E}
	condition:
		$0 at pe.entry_point
}