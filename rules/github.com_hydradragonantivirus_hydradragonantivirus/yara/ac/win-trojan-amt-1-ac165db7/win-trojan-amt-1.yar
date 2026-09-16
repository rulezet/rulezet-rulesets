rule Win_Trojan_Amt_1
{
strings:
	$a0 = { 3f4d5a7403e95301e8c9fcc41e4800268b470fb10cd3e0 }


condition:
	$a0
}