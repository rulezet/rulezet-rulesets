rule Win_Trojan_I13_14
{
strings:
	$a0 = { 7630a34101b440ba5602b95601cd21b800422bc999cd }


condition:
	$a0
}