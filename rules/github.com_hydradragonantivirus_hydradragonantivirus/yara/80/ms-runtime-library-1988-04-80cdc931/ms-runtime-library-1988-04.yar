import "pe"
rule _MS_RunTime_Library_1988_04_
{
	meta:
		description = "MS Run-Time Library 1988 (04)"
	strings:
		$0 = {1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB}
	condition:
		$0 at pe.entry_point
}