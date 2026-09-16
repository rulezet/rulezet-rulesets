rule Win_Trojan_Peed_133
{
strings:
	$a0 = { 68bdcaffff }

	$a1 = { bf419b409a01 }


condition:
	$a0 and $a1
}