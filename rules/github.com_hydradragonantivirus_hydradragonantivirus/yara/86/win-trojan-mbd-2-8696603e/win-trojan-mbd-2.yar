rule Win_Trojan_Mbd_2
{
strings:
	$a0 = { 81c62505b9fc041e33c08ed8eb02eb1566c706fc038034 }


condition:
	$a0
}