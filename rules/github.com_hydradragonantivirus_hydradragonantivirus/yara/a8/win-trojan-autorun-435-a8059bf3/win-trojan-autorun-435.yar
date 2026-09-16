rule Win_Trojan_Autorun_435
{
strings:
	$a0 = { 5b6175746f72756e5d }

	$a1 = { 7368656c6c5c325c636f6d6d616e643d72656379636c652e657865 }


condition:
	$a0 and $a1
}