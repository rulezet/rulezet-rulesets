import "pe"
rule _Gamehouse_Media_Protector_Version_Unknown_
{
	meta:
		description = "Gamehouse Media Protector Version Unknown"
	strings:
		$0 = {68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}