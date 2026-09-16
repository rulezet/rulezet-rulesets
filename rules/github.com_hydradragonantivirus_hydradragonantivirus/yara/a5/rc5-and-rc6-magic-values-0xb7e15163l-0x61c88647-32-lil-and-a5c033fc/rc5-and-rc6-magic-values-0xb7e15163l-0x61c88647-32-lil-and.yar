rule RC5_and_RC6_magic_values__0xb7e15163L_0x61C88647___32_lil_AND_
{
strings:
	$a0 = { 6351e1b7[0-20]4786c861 }

condition:
	$a0
}