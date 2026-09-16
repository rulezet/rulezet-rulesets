rule Win_Trojan_Swalker_1
{
strings:
	$a0 = { ff7511b801ff9dfa2e8e1621012e8b262301fbcf53 }


condition:
	$a0
}