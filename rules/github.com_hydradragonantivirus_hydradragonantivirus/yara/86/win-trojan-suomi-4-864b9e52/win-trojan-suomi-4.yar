rule Win_Trojan_Suomi_4
{
strings:
	$a0 = { e800005deb02905881ed3800e8c3 }


condition:
	$a0
}