rule Win_Trojan_Copyright_1
{
strings:
	$a0 = { fa8cc803060c015033c050cb }


condition:
	$a0
}