rule Win_Trojan_Small_4524
{
strings:
	$a0 = { ba2196e70f81ea2164a50f5252e83d00 }


condition:
	$a0
}