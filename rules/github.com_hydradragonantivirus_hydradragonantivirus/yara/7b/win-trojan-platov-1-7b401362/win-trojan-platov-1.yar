rule Win_Trojan_Platov_1
{
strings:
	$a0 = { 0a008cc80501008ed833c08ec026803e82011c7404e9ad00cea067072ea20001a068072ea20101a069072ea202018c }


condition:
	$a0
}