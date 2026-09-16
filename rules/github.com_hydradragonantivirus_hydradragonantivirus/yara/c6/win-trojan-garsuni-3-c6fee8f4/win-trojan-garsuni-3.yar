rule Win_Trojan_Garsuni_3
{
strings:
	$a0 = { 466c617368506c61796572496e7374616c6c65722e657865 }

	$a1 = { 4e65747a53746172746572 }

	$a2 = { 4e65747a537566666978 }


condition:
	$a0 and $a1 and $a2
}