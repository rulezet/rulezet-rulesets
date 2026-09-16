rule Win_Trojan_Subsys_23
{
strings:
	$a0 = { e136074c8880a58ee165e3d274ef39654e6d8c46667bc03e4fa22bbb5c77c43a4ed0827f2f745eb46ec9c2ec39802a13 }


condition:
	$a0
}