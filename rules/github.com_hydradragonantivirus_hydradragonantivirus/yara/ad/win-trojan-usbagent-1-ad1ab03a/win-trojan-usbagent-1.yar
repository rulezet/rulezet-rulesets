rule Win_Trojan_Usbagent_1
{
strings:
	$a0 = { 7368656c6c657865637574653d2e5c72656379636c65725c72656379636c65725c }

	$a1 = { 2e657865 }


condition:
	$a0 and $a1
}