rule Win_Trojan_Aznar_1
{
strings:
	$a0 = { 505351521e0656570e1fb8cacacd2181fbea0f745e }


condition:
	$a0
}