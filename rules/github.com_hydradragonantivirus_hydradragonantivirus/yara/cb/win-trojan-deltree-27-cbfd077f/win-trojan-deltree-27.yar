rule Win_Trojan_Deltree_27
{
strings:
	$a0 = { 425245414b204f46460d0a44454c545245452f7920433a5c2a2e2a }


condition:
	$a0
}