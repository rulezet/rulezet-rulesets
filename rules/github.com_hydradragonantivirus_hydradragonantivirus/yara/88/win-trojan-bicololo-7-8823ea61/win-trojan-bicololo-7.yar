rule Win_Trojan_Bicololo_7
{
strings:
	$a0 = { 73657475705f6666662e657865 }

	$a1 = { 636c725f67672e657865 }


condition:
	$a0 and $a1
}