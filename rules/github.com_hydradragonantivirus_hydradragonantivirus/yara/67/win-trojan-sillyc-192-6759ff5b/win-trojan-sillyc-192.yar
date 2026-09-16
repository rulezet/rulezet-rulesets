rule Win_Trojan_SillyC_192
{
strings:
	$a0 = { 5849eb02cd20e2fa2d06018be806b82035cd21b8cf90268707cd202687070749eb02cd20e2 }


condition:
	$a0
}