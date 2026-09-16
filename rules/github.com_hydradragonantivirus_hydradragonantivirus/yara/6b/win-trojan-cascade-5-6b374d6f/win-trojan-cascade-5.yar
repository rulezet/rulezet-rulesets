rule Win_Trojan_Cascade_5
{
strings:
	$a0 = { e800005b81eb070183bf010100740e8db72101b9340631 }


condition:
	$a0
}