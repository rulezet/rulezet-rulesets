rule Win_Trojan_VGOL_4
{
strings:
	$a0 = { 05fde8befc595a5888cbcd1626668f06900007c3b003cf0d0a0d0a090954686973207669727573 }


condition:
	$a0
}