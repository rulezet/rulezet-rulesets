rule Win_Trojan_Vengence_4
{
strings:
	$a0 = { 0e1fba8c03b80125cd21b003cd21b44abb5000cd21b85346bb0000b90200cd2f3dffff7503e9c201b85346bb0000b90300cd2f }


condition:
	$a0
}