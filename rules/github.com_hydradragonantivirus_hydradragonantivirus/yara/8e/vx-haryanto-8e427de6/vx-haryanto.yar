import "pe"
rule _Vx_Haryanto_
{
	meta:
		description = "Vx: Haryanto"
	strings:
		$0 = {81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB}
	condition:
		$0 at pe.entry_point
}