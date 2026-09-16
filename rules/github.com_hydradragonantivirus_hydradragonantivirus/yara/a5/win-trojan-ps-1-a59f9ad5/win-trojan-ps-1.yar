rule Win_Trojan_PS_1
{
strings:
	$a0 = { be6400b989018134????4646e2f8e800005e4c4c5d3bf5751081ed1101b94d01 }


condition:
	$a0
}