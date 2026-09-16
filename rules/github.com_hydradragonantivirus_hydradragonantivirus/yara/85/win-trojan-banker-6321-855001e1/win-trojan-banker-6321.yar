rule Win_Trojan_Banker_6321
{
strings:
	$a0 = { 6b6565702d616c697665 }

	$a1 = { 434c4f5345 }

	$a2 = { 5c52756e }

	$a3 = { 535c73797374656d33325c6363417070702e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}