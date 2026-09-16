rule Win_Trojan_VGEN_328
{
strings:
	$a0 = { 3dba6703cd2193b002e83401a372038916700387ca8bd081ea8813b80042cd21b43fb98813ba8008cd21be8008b9 }


condition:
	$a0
}