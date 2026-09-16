import "pe"
rule _SVKProtector_v111_
{
	meta:
		description = "SVK-Protector v1.11"
	strings:
		$0 = {60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 ?? ?? ?? ?? 5D 81 ED 10 ?? ?? ?? EB 03 C7 84 E9 64 A0 23 ?? ?? ??}
	condition:
		$0 at pe.entry_point
}