rule Win_Trojan_Alarm_2
{
strings:
	$a0 = { 1e0e0e1f07b110bf??????????03fd03f5ac86c4e4405032e080fc905875f5 }


condition:
	$a0
}