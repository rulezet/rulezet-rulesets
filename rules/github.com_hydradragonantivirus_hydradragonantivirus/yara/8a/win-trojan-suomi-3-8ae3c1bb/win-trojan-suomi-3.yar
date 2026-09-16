rule Win_Trojan_Suomi_3
{
strings:
	$a0 = { e800005deb02905381ed3800e8c3 }


condition:
	$a0
}