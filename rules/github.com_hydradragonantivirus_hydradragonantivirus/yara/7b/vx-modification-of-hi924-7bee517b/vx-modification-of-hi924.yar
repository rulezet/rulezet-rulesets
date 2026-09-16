import "pe"
rule _Vx_Modification_of_Hi924_
{
	meta:
		description = "Vx: Modification of Hi.924"
	strings:
		$0 = {50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B}
	condition:
		$0 at pe.entry_point
}