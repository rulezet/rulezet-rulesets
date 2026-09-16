rule Win_Trojan_Haxspy_6
{
strings:
	$a0 = { 668cd8a804751e6a006a006a036a006a0068000000c06850410010e872130000 }


condition:
	$a0
}