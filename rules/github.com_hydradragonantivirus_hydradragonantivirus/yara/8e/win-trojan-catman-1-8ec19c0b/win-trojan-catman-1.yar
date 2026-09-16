rule Win_Trojan_Catman_1
{
strings:
	$a0 = { be4c00bf0004ff34ff7402ff741c }


condition:
	$a0
}