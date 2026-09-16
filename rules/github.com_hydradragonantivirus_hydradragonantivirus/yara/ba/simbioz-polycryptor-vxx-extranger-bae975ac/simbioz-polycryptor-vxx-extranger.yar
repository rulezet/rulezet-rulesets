import "pe"
rule _SimbiOZ_PolyCryptor_vxx_Extranger_
{
	meta:
		description = "SimbiOZ PolyCryptor v.xx-> Extranger"
	strings:
		$0 = {55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8}
	condition:
		$0 at pe.entry_point
}