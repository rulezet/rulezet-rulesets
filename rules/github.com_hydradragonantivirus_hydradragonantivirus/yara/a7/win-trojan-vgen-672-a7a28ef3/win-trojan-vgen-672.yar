rule Win_Trojan_VGEN_672
{
strings:
	$a0 = { e90400cd200000568bfe03740256a5a55e8d545cb44ecd217244ba9e00b8023de83300722a93b43fcd21803c4d741c }


condition:
	$a0
}