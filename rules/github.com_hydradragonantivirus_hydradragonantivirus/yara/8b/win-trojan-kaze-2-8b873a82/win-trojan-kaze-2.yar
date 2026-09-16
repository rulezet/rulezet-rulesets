rule Win_Trojan_Kaze_2
{
strings:
	$a0 = { 6a00e88502000048740661e974ffffff61e976f2ffff }


condition:
	$a0
}