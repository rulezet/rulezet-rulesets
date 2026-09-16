rule Win_Trojan_Y_13
{
strings:
	$a0 = { 6cbb0100ba1000be3603b123e81501720fb74093b9320399e80901b43ee80401071fe97cffc3 }


condition:
	$a0
}