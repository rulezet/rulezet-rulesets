rule Win_Trojan_Vengence_8
{
strings:
	$a0 = { 8cc88ed8b85346bb0000b90200cd2f3dffff7503e9fc00b8 }


condition:
	$a0
}