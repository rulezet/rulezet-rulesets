import "pe"
rule _EXE__Liuli_
{
	meta:
		description = "EXE�ļ��ϲ��� -> Liuli"
	strings:
		$0 = {E8 53 03 00 00 8B F0 56 56 E8 98 03 00 00 8B C8}
	condition:
		$0 at pe.entry_point
}