rule Win_Trojan_Ghost_5
{
strings:
	$a0 = { 07cbbad603eb03badb03b9050090b440bb0200cd21b9270090bae003b440cd21eaed010000 }


condition:
	$a0
}