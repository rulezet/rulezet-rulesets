rule Win_Trojan_Vengence_E_1
{
strings:
	$a0 = { b44abb5000cd218cc88ed8b85346bb0000b90200cd2f3dffff7503e9ad01b85346bb0000b90300cd2f3dffff7503e99a01b85346bb0000b90400cd2f3dffff75 }


condition:
	$a0
}