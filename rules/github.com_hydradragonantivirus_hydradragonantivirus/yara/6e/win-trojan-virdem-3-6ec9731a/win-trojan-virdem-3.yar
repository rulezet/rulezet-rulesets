rule Win_Trojan_Virdem_3
{
strings:
	$a0 = { 431e8cc08ed88bd3b43bcd211fbe5203 }


condition:
	$a0
}