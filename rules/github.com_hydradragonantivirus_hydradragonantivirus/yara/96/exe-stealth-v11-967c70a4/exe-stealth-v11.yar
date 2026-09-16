import "pe"
rule _EXE_Stealth_v11_
{
	meta:
		description = "EXE Stealth v1.1"
	strings:
		$0 = {EB ?? 60 EB ?? E8 ?? ?? ?? ?? 5D 81 ED D3 26}
	condition:
		$0 at pe.entry_point
}