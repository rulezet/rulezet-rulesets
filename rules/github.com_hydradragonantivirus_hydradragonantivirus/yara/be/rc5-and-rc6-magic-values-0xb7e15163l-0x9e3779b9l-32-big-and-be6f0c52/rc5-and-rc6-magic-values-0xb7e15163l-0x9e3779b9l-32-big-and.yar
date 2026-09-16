rule RC5_and_RC6_magic_values__0xb7e15163L_0x9e3779b9L___32_big_AND_
{
strings:
	$a0 = { b7e15163[0-20]9e3779b9 }

condition:
	$a0
}