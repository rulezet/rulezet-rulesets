rule Win_Trojan_Nop_2
{
strings:
	$a0 = { 02005500010002000100000000007a000000080000008d08 }


condition:
	$a0
}