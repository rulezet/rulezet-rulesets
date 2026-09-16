import "pe"
rule _CrackStop_v101_c_Stefan_Esser_1997_
{
	meta:
		description = "CrackStop v1.01 (c) Stefan Esser 1997"
	strings:
		$0 = {B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC}
	condition:
		$0 at pe.entry_point
}