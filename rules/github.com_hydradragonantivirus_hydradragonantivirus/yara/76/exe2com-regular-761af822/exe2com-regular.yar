import "pe"
rule _EXE2COM_regular_
{
	meta:
		description = "EXE2COM (regular)"
	strings:
		$0 = {E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D}
	condition:
		$0 at pe.entry_point
}