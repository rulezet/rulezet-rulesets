rule Win_Trojan_Intrep_1
{
strings:
	$a0 = { fa007414b910002bca8be901ad5e04839560040040 }


condition:
	$a0
}