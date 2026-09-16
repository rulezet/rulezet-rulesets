import "pe"
rule _Netopsystems_FEAD_Optimizer_
{
	meta:
		description = "Netopsystems FEAD Optimizer"
	strings:
		$0 = {E8 00 00 00 00 58 BB 00 00 40 00 8B}
		$1 = {60 BE 00 50 43 00 8D BE 00 C0 FC FF}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}