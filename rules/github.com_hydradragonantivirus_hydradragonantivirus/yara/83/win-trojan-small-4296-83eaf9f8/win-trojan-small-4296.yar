rule Win_Trojan_Small_4296
{
strings:
	$a0 = { 56575355e8[0-30]6a006a006a00ffd2 }


condition:
	$a0
}