rule Win_Trojan_BANE256A_1
{
strings:
	$a0 = { 5fb86300abb82000ab0e1f33f6bf0002b90001f3a40e5801062200b40dcd215833d22eff2e2000 }


condition:
	$a0
}