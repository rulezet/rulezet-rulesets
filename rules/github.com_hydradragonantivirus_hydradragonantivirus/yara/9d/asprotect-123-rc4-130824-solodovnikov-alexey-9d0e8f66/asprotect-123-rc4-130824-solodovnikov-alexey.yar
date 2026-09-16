import "pe"
rule _ASProtect_123_RC4__130824__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.23 RC4 - 1.3.08.24 -> Solodovnikov Alexey"
	strings:
		$0 = {68 01 ?? ?? 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at pe.entry_point
}