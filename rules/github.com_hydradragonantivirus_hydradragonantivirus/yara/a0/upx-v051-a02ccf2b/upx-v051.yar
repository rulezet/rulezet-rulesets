import "pe"
rule _UPX_v051_
{
	meta:
		description = "UPX v0.51"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 8D B0}
	condition:
		$0 at pe.entry_point
}