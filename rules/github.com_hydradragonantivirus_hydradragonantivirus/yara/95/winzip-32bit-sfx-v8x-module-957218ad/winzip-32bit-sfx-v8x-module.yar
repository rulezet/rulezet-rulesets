import "pe"
rule _WinZip_32bit_SFX_v8x_module_
{
	meta:
		description = "WinZip 32-bit SFX v8.x module"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? 90 90 90 ?? ??}
	condition:
		$0 at pe.entry_point
}