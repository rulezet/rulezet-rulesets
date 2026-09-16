rule Win_Trojan_ASP_32
{
strings:
	$a0 = { b1a3b4e6ceaa3a[0-45]3c253d666f6c64657270617468253e5c66696c652e657865[0-68]3dcfc2d4d8 }


condition:
	$a0
}