rule Win_Trojan_FindMe_1
{
strings:
	$a0 = { ba8000cd6ab404cd1a81fa2305740681fa26127509b9ff00e670e671e2facbba0001cd6a72df }


condition:
	$a0
}