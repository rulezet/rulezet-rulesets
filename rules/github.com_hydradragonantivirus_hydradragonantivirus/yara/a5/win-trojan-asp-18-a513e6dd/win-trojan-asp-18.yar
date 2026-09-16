rule Win_Trojan_ASP_18
{
strings:
	$a0 = { 757365722069643d7361222027c7ebbdab7777772e3936636e2e636f6db8c4ceaac4bfb1eab5c473716c }


condition:
	$a0
}