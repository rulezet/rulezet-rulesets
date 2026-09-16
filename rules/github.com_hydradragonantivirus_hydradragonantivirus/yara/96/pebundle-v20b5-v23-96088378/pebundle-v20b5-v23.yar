import "pe"
rule _PEBundle_v20b5__v23_
{
	meta:
		description = "PEBundle v2.0b5 - v2.3"
	strings:
		$0 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 83}
	condition:
		$0 at pe.entry_point
}