rule Win_Trojan_KbrBug_2
{
strings:
	$a0 = { 94002e8b85470bbb0b0ab93c012e300143e2fae8b0fe }


condition:
	$a0
}