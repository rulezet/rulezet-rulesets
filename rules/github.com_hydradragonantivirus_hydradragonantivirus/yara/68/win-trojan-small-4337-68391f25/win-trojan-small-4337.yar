rule Win_Trojan_Small_4337
{
strings:
	$a0 = { e8??000000(e9|e8)??000000[0-255]bb999bedfd81eb999badfd81e889c02626058936272653 }


condition:
	$a0
}