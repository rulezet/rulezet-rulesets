rule Win_Trojan_Whale_26
{
strings:
	$a0 = { 03004033de0bf6fec75b81eba12383 }


condition:
	$a0
}