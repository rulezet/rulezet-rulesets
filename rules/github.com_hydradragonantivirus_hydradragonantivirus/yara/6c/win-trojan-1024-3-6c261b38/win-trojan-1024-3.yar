rule Win_Trojan_1024_3
{
strings:
	$a0 = { 012ea30300b4400e1fba0004b90004e8e8007230 }


condition:
	$a0
}