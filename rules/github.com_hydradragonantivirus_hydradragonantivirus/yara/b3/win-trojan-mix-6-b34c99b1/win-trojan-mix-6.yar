rule Win_Trojan_Mix_6
{
strings:
	$a0 = { bbd0014000bf00104000be0060400053e80a00000002d275058a164612d2 }


condition:
	$a0
}