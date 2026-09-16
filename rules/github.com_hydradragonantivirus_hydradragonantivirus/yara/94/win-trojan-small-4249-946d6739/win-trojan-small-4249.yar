rule Win_Trojan_Small_4249
{
strings:
	$a0 = { c1f8c9e8ac050000819d670190cc5e81 }


condition:
	$a0
}