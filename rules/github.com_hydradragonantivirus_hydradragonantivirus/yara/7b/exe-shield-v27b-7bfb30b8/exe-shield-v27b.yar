import "pe"
rule _Exe_Shield_v27b_
{
	meta:
		description = "Exe Shield v2.7b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0B 20 40 ?? B9 EB 08 ?? ?? 8D BD 53 20 40 ?? 8B F7 AC}
	condition:
		$0 at pe.entry_point
}