rule Win_Trojan_Nostardamus_4
{
strings:
	$a0 = { d642214daf1ba6a229a7af8282972cbb9f4dd2d66f9f4fd4d667e540498c64a411a5a21af6d797f6 }


condition:
	$a0
}