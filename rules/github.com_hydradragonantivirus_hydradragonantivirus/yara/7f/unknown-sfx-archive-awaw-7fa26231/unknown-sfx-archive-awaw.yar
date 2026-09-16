import "pe"
rule _Unknown_SFX_Archive_aWAW_
{
	meta:
		description = "Unknown SFX Archive (aWAW)"
	strings:
		$0 = {61 57 41 57}
	condition:
		$0 at pe.entry_point
}