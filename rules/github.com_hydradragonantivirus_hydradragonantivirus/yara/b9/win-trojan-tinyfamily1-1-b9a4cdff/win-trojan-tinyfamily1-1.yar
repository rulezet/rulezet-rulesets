rule Win_Trojan_TinyFamily1_1
{
strings:
	$a0 = { b43ecd32071f5f5a595b582eff2e }


condition:
	$a0
}