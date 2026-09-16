rule Win_Trojan_Kela_9
{
strings:
	$a0 = { ffffcd210e1f8ec0bf00018bf5b9e803f3a61f077503e9 }


condition:
	$a0
}