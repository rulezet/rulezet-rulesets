import "pe"
rule _NoobyProtect_SE_Public_V1100__Nooby__20081226_
{
	meta:
		description = "NoobyProtect SE Public V1.1.0.0 -> Nooby * 20081226"
	strings:
		$0 = {4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 31 2E 30 2E 30}
	condition:
		$0 at pe.entry_point
}