rule Win_Trojan_Press_1
{
strings:
	$a0 = { ffba00fccd217303e9d300b43f5a5281c27402b91c00 }


condition:
	$a0
}