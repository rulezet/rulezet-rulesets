rule Win_Trojan_T_2
{
strings:
	$a0 = { eb0b905dca0400558bec5dca062e8c9cf407eb0b90cb558bec5dca0c000000eb0b902e6768696d6465666b61e8 }


condition:
	$a0
}