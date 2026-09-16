rule Win_Trojan_Cascade_13
{
strings:
	$a0 = { 5b81eb3001be820689da81c24d0189df31954d0131b54d0142474e75f3 }


condition:
	$a0
}