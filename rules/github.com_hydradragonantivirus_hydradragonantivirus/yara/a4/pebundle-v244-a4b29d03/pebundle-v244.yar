import "pe"
rule _PEBundle_v244_
{
	meta:
		description = "PEBundle v2.44"
	strings:
		$0 = {EB 06 68 C3 9C 60 BD B9 02 B0 90 8D BD F3 AA 01 AD FF}
	condition:
		$0 at pe.entry_point
}