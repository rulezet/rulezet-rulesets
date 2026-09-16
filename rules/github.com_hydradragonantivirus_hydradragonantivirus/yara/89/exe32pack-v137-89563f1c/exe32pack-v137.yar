import "pe"
rule _EXE32Pack_v137_
{
	meta:
		description = "EXE32Pack v1.37"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 02 81 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D}
	condition:
		$0 at pe.entry_point
}