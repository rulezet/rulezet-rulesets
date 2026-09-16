rule Win_Trojan_Interceptor_1
{
strings:
	$a0 = { 8000b43fb90300ba0a0003d6cd2172 }


condition:
	$a0
}