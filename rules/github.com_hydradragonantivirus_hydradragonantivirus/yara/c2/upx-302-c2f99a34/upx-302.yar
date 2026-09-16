import "pe"
rule _UPX_302_
{
	meta:
		description = "UPX 3.02"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C}
	condition:
		$0 at pe.entry_point
}