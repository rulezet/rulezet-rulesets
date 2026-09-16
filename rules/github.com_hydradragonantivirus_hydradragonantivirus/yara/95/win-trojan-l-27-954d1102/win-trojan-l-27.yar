rule Win_Trojan_L_27
{
strings:
	$a0 = { e955018b1e580253e810005bb98b02ba0001b440cd21e80200c3 }


condition:
	$a0
}