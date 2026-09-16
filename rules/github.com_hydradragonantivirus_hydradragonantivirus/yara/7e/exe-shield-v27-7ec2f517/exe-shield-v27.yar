import "pe"
rule _Exe_Shield_v27_
{
	meta:
		description = "Exe Shield v2.7"
	strings:
		$0 = {EB 06 68 40 85 06 ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 30 90 40 ?? 90 90 01 85 DA 90 40 ??}
	condition:
		$0 at pe.entry_point
}