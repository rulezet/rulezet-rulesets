rule Win_Trojan_Civilwar_2
{
strings:
	$a0 = { 9f7ed7c73005e6b3c4f2c13005cab3c4f2b6300586b3c54632c13005d6b3c4e2b5300146b3c4e2b6 }


condition:
	$a0
}