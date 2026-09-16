import "pe"
rule _ExeShield_Protector_36__wwwexeshieldcom_
{
	meta:
		description = "ExeShield Protector 3.6 -> www.exeshield.com"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC}
		$1 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}