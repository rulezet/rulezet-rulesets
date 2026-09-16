rule Win_Trojan_Explorer_4
{
strings:
	$a0 = { e8000000005981e905000000??????eb02ebfb }


condition:
	$a0
}