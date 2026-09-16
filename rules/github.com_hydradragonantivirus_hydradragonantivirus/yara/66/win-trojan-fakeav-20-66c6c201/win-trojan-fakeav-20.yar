rule Win_Trojan_Fakeav_20
{
strings:
	$a0 = { 558bec83c4f8608d3d50bdbc71c1cb1781 }

	$a1 = { 50082f2d5668294d54482b6d5a58256d5858276d5e5821 }


condition:
	$a0 and $a1
}