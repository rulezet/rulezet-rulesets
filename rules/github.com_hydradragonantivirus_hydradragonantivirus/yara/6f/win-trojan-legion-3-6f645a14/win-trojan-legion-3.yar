rule Win_Trojan_Legion_3
{
strings:
	$a0 = { 2666736f61667777716a2e[0-18]2926225c74656d702e7662732522 }


condition:
	$a0
}