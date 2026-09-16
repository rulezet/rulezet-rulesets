rule Win_Trojan_XDog_1
{
strings:
	$a0 = { e604e9c606e904ad8b1efa04b9dc05ba0001b4409cff1ede048b1efa04b90000ba0000b000b4 }


condition:
	$a0
}