rule Win_Trojan_Delf_11
{
strings:
	$a0 = { b0e8e2ebffffc3e958e6ffffebe05f5e5be89aeaffff0000ffffffff010000005c000000ffffffff0c00000073797374656d78702e657865000000006f70656e }


condition:
	$a0
}