rule Win_Trojan_CSE_1
{
strings:
	$a0 = { 595b53b800908ed833d2b440cd21 }


condition:
	$a0
}