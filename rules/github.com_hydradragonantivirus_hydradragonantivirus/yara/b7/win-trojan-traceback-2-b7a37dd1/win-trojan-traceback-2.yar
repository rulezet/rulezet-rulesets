rule Win_Trojan_Traceback_2
{
strings:
	$a0 = { 81e1fe00b80143e8bbfe7291b802 }


condition:
	$a0
}