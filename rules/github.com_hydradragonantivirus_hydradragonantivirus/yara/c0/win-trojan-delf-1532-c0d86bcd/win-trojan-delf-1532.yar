rule Win_Trojan_Delf_1532
{
strings:
	$a0 = { b80c87400033d2e80cfcffffb81087400033d2e800fcffffb81487400033d2e8f4fbffffb81887400033d2e8e8fbffffb83487400033d2e8dcfbffffb83487400033d2e8d0fbffff }


condition:
	$a0
}