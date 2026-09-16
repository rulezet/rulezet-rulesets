rule Win_Trojan_Dropper_4
{
strings:
	$a0 = { 03bb7205b90927ba0001cd1359730e }


condition:
	$a0
}