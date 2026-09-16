rule Win_Trojan_Induc_3
{
strings:
	$a0 = { ff64240400f9e925e4ffff000000a58c0b3a1efc060000000000000000003efc06002efc060026fc06 }


condition:
	$a0
}