rule Win_Trojan_Junk_2
{
strings:
	$a0 = { 0200550005000000ffff01030000930d0000050000000103 }


condition:
	$a0
}