rule Win_Trojan_Andy_2
{
strings:
	$a0 = { c502b90300b440cd212e8b1ec10253b00233c933d2b442cd212e8e1ed60233d25bb9e603b4 }


condition:
	$a0
}