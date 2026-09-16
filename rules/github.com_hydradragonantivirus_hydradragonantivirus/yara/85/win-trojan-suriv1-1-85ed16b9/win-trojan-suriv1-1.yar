rule Win_Trojan_Suriv1_1
{
strings:
	$a0 = { 1fb42acd2181f9c407721b81fa0104 }


condition:
	$a0
}