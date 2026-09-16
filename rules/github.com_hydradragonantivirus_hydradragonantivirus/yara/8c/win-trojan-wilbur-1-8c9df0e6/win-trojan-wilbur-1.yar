rule Win_Trojan_Wilbur_1
{
strings:
	$a0 = { 8bf581c6c0018bfeb920008b9eb801fcad33c3abe2fa }


condition:
	$a0
}