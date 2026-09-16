rule Win_Trojan_Small_4336
{
strings:
	$a0 = { e8??000000(e9|e8)??000000[0-255]bb999bedfd81eb999badfde9??000000 }


condition:
	$a0
}