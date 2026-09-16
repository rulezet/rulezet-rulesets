import "pe"
rule _UPX_v081__v084_Modified_
{
	meta:
		description = "UPX v0.81 - v0.84 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at pe.entry_point
}