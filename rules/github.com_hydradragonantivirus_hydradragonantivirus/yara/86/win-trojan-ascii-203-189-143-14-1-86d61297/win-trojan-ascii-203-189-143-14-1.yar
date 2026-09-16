rule Win_Trojan_Ascii_203_189_143_14_1
{
strings:
	$a0 = { 3230332e3138392e3134332e3134 }


condition:
	$a0
}