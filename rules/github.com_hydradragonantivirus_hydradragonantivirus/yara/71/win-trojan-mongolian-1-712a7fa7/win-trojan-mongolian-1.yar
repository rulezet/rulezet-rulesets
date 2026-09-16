rule Win_Trojan_Mongolian_1
{
strings:
	$a0 = { 13044848a31304b94000f7e18ec033dbb90727b6012e8a16007db80302cd1372f906b8730150cb }


condition:
	$a0
}