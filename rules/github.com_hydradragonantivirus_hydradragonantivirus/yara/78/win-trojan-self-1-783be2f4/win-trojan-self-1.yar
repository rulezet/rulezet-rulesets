rule Win_Trojan_Self_1
{
strings:
	$a0 = { ba0501b90600b44ecd217303e9b900 }


condition:
	$a0
}