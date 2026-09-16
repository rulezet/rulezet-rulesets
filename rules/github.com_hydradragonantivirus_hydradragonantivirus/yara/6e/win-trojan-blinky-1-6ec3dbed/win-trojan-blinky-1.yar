rule Win_Trojan_Blinky_1
{
strings:
	$a0 = { 260901b9c204be0c018bfefcac32c4aae2fac30e070e1f }


condition:
	$a0
}