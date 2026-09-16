import "pe"
rule _Unknown_SFX_Archive_IDSKA32_
{
	meta:
		description = "Unknown SFX Archive (IDSKA32)"
	strings:
		$0 = {69 64 73 6B 61 33 32}
	condition:
		$0 at pe.entry_point
}