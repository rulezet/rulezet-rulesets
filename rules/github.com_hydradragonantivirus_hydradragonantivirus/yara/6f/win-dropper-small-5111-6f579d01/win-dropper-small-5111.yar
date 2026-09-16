rule Win_Dropper_Small_5111
{
strings:
	$a0 = { 8bd08d85d4feffffe8caeeffff8b85d4feffffbacc294000e8aaefffff751a8b4608506a006a10e86bf6ffffa39c51400053e8f8f5ffffeb0d }


condition:
	$a0
}