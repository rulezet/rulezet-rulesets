import "pe"
rule _SecureEXE_30__ZipWorx_
{
	meta:
		description = "SecureEXE 3.0 -> ZipWorx"
	strings:
		$0 = {E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}