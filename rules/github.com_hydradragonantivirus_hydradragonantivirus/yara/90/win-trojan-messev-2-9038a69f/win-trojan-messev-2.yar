rule Win_Trojan_Messev_2
{
strings:
	$a0 = { 0c02e6210e1f8bdeb90f0c8037fa43b409ba0f0c03 }


condition:
	$a0
}