import "pe"
rule _NoobyProtect_V1290__Nooby__20090218_
{
	meta:
		description = "NoobyProtect V1.2.9.0 -> Nooby * 20090218"
	strings:
		$0 = {E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 32 2E 39 2E 30}
	condition:
		$0 at pe.entry_point
}