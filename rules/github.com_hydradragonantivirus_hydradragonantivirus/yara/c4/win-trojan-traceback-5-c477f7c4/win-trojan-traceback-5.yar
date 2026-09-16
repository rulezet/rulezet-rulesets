rule Win_Trojan_Traceback_5
{
strings:
	$a0 = { e87106e82806b419cd2189b451018184 }


condition:
	$a0
}