rule Win_Trojan_Funfun_1
{
strings:
	$a0 = { 8e06000000ffffa01e0000b508000005000000a01e }


condition:
	$a0
}