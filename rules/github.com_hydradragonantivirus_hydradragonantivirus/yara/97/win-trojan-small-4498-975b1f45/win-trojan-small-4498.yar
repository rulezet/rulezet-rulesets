rule Win_Trojan_Small_4498
{
strings:
	$a0 = { 5589e56800??4000e817000000e81d000000ad01d035????????8946fc39f375 }


condition:
	$a0
}