import "pe"
rule _Unknown_Protected_Mode_compiler_1_
{
	meta:
		description = "Unknown Protected Mode compiler (1)"
	strings:
		$0 = {FA BC ?? ?? 8C C8 8E D8 E8 ?? ?? E8 ?? ?? E8 ?? ?? 66 B8 ?? ?? ?? ?? 66 C1}
	condition:
		$0 at pe.entry_point
}