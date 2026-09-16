rule Win_Trojan_Onlinegames_22
{
strings:
	$a0 = { 558bec81c4c4feffffe802000b57e8020007350bc07505 }

	$a1 = { 53656c6644656c2e626174 }

	$a2 = { 67616d652e657865 }


condition:
	$a0 and $a1 and $a2
}