rule Win_Trojan_Mybot_8267
{
strings:
	$a0 = { a35858077a0e1fc08878d9b23cf9f252a164d08022ebfa9160ef644684dad5c6e39552768731bc07dd76cf1710f1dfe2dabf9c95f058fb5ecbeb94e38951c5e6c7c4aed064b7 }


condition:
	$a0
}