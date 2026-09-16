rule Win_Trojan_Kaze_3
{
strings:
	$a0 = { 6a00e8950e000048740661e974ffffff6160e985eeffff }


condition:
	$a0
}