rule Win_Trojan_Whale_22
{
strings:
	$a0 = { eb15e8e6ff75fb585bfb59ff3666 }


condition:
	$a0
}