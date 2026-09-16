import "pe"
rule _Symantec_C_v400_p_Libraries_
{
	meta:
		description = "Symantec C v4.00 + Libraries"
	strings:
		$0 = {FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26}
	condition:
		$0 at pe.entry_point
}