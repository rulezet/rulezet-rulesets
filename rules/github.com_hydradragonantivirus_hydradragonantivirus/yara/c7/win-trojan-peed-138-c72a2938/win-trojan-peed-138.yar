rule Win_Trojan_Peed_138
{
strings:
	$a0 = { f7da87cb755889e00110c3ba0400000087d181c4 }


condition:
	$a0
}