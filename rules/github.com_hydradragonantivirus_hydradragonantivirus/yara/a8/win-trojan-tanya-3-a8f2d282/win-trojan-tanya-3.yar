rule Win_Trojan_Tanya_3
{
strings:
	$a0 = { e800005b83eb03b9d007be00000e1fb04730401cc0c803fec846e2f5 }


condition:
	$a0
}