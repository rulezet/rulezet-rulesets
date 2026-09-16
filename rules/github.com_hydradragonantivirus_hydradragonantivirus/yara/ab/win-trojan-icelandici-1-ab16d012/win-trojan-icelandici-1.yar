rule Win_Trojan_IcelandicI_1
{
strings:
	$a0 = { 2ec60687020a9050535152561e8bda43 }


condition:
	$a0
}