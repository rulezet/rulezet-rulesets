import "pe"
rule NTkrnlSecureSuite__NTkrnlTeam_Blue_
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite -> NTkrnl Team (Blue)"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 29 19 43 00 E8 01 00 00 00 C3 C3 A2 A9 61 4E A5 0E C7 A6 59 90 6E 4D 4C DB 36 46 FB 6E C4 45 A3 C2 2E 0E 41 59 1A 50 17 39 62 4D B8 61 24 8E CF D1 0E 9E 7A 66 C0 8D 6B 9C 52 7E 96 46 80 AF }
	condition:
		$a0 at pe.entry_point
}