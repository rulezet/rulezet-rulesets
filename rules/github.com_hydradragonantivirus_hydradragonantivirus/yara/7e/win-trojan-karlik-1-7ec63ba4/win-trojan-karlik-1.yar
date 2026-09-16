rule Win_Trojan_Karlik_1
{
strings:
	$a0 = { 7ef9e8fbfe72cfb44033c9e8f2fe72c6b8004233c98bd1e8e6fe72bab440b91c00ba2d00e8d9fe }


condition:
	$a0
}