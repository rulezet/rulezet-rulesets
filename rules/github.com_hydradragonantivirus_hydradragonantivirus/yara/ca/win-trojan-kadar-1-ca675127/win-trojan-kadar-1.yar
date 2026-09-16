rule Win_Trojan_Kadar_1
{
strings:
	$a0 = { b84441484b8b[0-9]4441524b }

	$a1 = { 4461726b204861636b65722032303034 }

	$a2 = { 6e6400633a5c616d737475622e657865 }


condition:
	$a0 and $a1 and $a2
}