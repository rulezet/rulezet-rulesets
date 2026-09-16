rule Win_Trojan_Pakes_981
{
strings:
	$a0 = { 505351f85256570f83ccffffffd6e484761ce6c61b31e165cc }

	$a1 = { 6470312e666e65 }

	$a2 = { 53c267b26db76b9152904f5a5ec867 }


condition:
	$a0 and $a1 and $a2
}