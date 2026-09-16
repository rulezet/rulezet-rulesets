rule Win_Trojan_BW_Mayberry_1
{
strings:
	$a0 = { 30013e3b963402744381c230013e899630028d963302cd21b440b92d018d960601cd2132c0e8 }


condition:
	$a0
}