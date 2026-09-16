rule Win_Trojan_SillyC_50
{
strings:
	$a0 = { f077232d030089869500b440b99e008bd5cd21b8004233c999cd21b440b904008d969400cd21 }


condition:
	$a0
}