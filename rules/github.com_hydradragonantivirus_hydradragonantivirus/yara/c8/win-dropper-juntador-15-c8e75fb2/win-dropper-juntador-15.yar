rule Win_Dropper_Juntador_15
{
strings:
	$a0 = { 2e65786500000000ffffffff060000005c74656d705c0000ffffffff030000004a554e00ffffffff03000000415f3000 }


condition:
	$a0
}