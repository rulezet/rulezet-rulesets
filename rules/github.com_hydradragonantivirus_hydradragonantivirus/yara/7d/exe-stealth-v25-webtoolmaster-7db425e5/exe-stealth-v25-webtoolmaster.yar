import "pe"
rule _EXE_Stealth_v25__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.5 -> WebToolMaster"
	strings:
		$0 = {60 90 EB 22 45 78 65 53 74 65 61 6C 74 68}
	condition:
		$0 at pe.entry_point
}