rule Win_Trojan_Hybris_21
{
strings:
	$a0 = { 3629ced72a67a34a5c3812 }

	$a1 = { 6629ce072b67d34a5c6812 }

	$a2 = { a29dfad81918d74c9fc09abf1968 }

	$a3 = { 1881c3040000004875f16800104000c3 }


condition:
	$a0 and $a1 and $a2 and $a3
}