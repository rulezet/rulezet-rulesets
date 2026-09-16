rule Win_Trojan_VP_3
{
strings:
	$a0 = { 2903b90100ba0000bb7c03cd267312 }


condition:
	$a0
}