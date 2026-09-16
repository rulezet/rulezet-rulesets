rule Win_Trojan_Delf_1677
{
strings:
	$a0 = { 6801a00501e801000000c3c3f3e0f609583ea40919951229f71748fcf5aa95e87af2058c7d6a576a27923e }


condition:
	$a0
}