rule Win_Trojan_Trackswap_2
{
strings:
	$a0 = { a1130448a31304b106d3e08ec006bd }


condition:
	$a0
}