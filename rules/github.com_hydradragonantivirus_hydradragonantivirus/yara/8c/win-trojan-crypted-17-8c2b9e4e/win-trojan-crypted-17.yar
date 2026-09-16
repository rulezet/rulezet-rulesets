rule Win_Trojan_Crypted_17
{
strings:
	$a0 = { 684433221160e838030000 }

	$a1 = { 8b3c24b9ce0000008137????????afe2f7c3 }


condition:
	$a0 and $a1
}