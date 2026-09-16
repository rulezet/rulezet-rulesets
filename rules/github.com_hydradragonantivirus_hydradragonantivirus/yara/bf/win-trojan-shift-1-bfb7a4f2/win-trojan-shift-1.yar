rule Win_Trojan_Shift_1
{
strings:
	$a0 = { e800005e83ee031e060e1f80bcdc05487515c684cb0548b9060083ee060e07bf0001fcf3a4eb28c684cb05478b84df05 }


condition:
	$a0
}