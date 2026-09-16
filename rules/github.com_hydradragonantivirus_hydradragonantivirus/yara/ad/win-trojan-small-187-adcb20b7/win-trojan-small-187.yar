rule Win_Trojan_Small_187
{
strings:
	$a0 = { ee03010e1f0e07b4fecd2180fcfe7415b90300bb00018a84920388074346e2f6b80001ffe0b9360381c600010e07 }


condition:
	$a0
}