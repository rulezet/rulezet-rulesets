import "pe"
rule _Turbo_C_1987_
{
	meta:
		description = "Turbo C 1987"
	strings:
		$0 = {FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21}
		$1 = {FB 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}