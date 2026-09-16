rule Win_Trojan_Virogen_10
{
strings:
	$a0 = { cebf0802cef99045cef99045cef9ce90cc45cef99045cef99045cef99045cef99045cef990b9e5079045cef990 }


condition:
	$a0
}