import "pe"
rule _NeoLite_vxx_
{
	meta:
		description = "NeoLite vx.x"
	strings:
		$0 = {E9 9B ?? ?? ??}
	condition:
		$0 at pe.entry_point
}