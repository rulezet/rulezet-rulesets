import "pe"
rule _EXE2COM_Limited_
{
	meta:
		description = "EXE2COM (Limited)"
	strings:
		$0 = {BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20}
	condition:
		$0 at pe.entry_point
}