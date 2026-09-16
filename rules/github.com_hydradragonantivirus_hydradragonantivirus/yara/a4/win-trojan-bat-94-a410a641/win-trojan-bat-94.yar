rule Win_Trojan_BAT_94
{
strings:
	$a0 = { 5c72656379636c65642072656e206463302e747874206463302e747874 }

	$a1 = { 6675636b6564 }


condition:
	$a0 and $a1
}