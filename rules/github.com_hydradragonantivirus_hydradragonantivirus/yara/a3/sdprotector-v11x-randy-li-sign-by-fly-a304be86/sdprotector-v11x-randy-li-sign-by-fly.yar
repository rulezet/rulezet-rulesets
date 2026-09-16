import "pe"
rule _SDProtector_V11X__Randy_Li__Sign_by_fly_
{
	meta:
		description = "SDProtector V1.1X -> Randy Li ! Sign by fly"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1}
	condition:
		$0 at pe.entry_point
}