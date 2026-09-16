rule Win_Trojan_Etop_3
{
strings:
	$a0 = { 02cd20e2fae800005849eb02cd20e2fa2d1b008be806b82035cd21b8cf90268707cd20268707 }


condition:
	$a0
}