rule Win_Trojan_Agent_35473
{
strings:
	$a0 = { 558becb9140000006a006a004975f9535657b8a07f40 }

	$a1 = { 6a78303831303137 }

	$a2 = { 5c67616d652e657865 }


condition:
	$a0 and $a1 and $a2
}