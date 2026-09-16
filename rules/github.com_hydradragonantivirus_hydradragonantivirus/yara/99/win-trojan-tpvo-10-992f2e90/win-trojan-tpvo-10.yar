rule Win_Trojan_TPVO_10
{
strings:
	$a0 = { 1b028d940001cd21b8004233c933d2cd21b440b918 }


condition:
	$a0
}