import "pe"
rule _Turbo_C_1988_
{
	meta:
		description = "Turbo C 1988"
	strings:
		$0 = {8C D8 BB ?? ?? 8E DB 8C D3 8B CC FA 8E ?? ?? ?? BC}
	condition:
		$0 at pe.entry_point
}