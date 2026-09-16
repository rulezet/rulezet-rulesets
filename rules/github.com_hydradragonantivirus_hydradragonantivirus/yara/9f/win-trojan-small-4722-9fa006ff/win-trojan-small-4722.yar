rule Win_Trojan_Small_4722
{
strings:
	$a0 = { 6c612e6461740000000077696e73652e657865000000687474 }


condition:
	$a0
}