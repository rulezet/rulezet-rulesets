rule Win_Trojan_Semtex_2
{
strings:
	$a0 = { 33ffb9803ef3a45e5f1f075a595b589d2eff2ec602 }


condition:
	$a0
}