rule Win_Trojan_Vengence_9
{
strings:
	$a0 = { b44abb5000cd218cc88ed8b85346bb0000b90200cd2f3dff }


condition:
	$a0
}