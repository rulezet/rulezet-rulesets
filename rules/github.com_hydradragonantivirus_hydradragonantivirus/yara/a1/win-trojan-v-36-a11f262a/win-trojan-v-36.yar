rule Win_Trojan_V_36
{
strings:
	$a0 = { 3dcd218cc68bd8c6444f00b80042b90000ba0000cd21 }


condition:
	$a0
}