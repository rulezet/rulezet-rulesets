rule Win_Trojan_TinyFamily2_1
{
strings:
	$a0 = { 268785e0feabe3f7931e07c33d004b75 }


condition:
	$a0
}