import "pe"
rule _Hide_PE_101__BGCorp_
{
	meta:
		description = "Hide PE 1.01 -> BGCorp"
	strings:
		$0 = {BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D}
	condition:
		$0 at pe.entry_point
}