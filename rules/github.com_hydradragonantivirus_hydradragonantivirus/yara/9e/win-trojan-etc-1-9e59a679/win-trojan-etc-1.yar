rule Win_Trojan_ETC_1
{
strings:
	$a0 = { ffffe2fea1fc00a30001a1fe00a30201 }


condition:
	$a0
}