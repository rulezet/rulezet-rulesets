rule Win_Trojan_Autorun_362
{
strings:
	$a0 = { 7368656c6c657865637574653d72656379636c65645c }

	$a1 = { 2e657865 }


condition:
	$a0 and $a1
}