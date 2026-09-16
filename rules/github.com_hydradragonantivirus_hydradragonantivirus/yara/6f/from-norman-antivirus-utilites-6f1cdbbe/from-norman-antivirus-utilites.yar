import "pe"
rule _from_NORMAN_AntiVirus_Utilites_
{
	meta:
		description = "from NORMAN Anti-Virus Utilites"
	strings:
		$0 = {E8 ?? ?? 5B 52 45 2F 4E 44 44 53 5D 0D 0A}
	condition:
		$0 at pe.entry_point
}