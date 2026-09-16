import "pe"
rule _ASPack_v107b_DLL__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.07b (DLL) -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5}
	condition:
		$0 at pe.entry_point
}