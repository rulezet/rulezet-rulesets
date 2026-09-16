rule Win_Trojan_Burghofer_3
{
strings:
	$a0 = { 215b488ec0fa26c7060100000026803e00005a7550 }


condition:
	$a0
}