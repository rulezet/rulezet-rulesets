import "pe"
rule _CodeSafe_v20_
{
	meta:
		description = "CodeSafe v2.0"
	strings:
		$0 = {CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1}
	condition:
		$0 at pe.entry_point
}