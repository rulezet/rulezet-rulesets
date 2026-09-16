rule Win_Trojan_Vengence_3
{
strings:
	$a0 = { d8b85346bb0000b90200cd2f3dffff7503e9fc00b85346bb0000b90300cd2f3dffff7503e9e900b85346bb0000b90400cd2f3dffff7503e9d600b85346 }


condition:
	$a0
}