rule Win_Trojan_Karol_1
{
strings:
	$a0 = { 8ede8ec6be5000bf010087360000873e0200b452cd21 }


condition:
	$a0
}