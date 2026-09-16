rule Win_Trojan_Trivial_456
{
strings:
	$a0 = { b44eba1f0133c9cd21ba9e00b8013dcd218bd8b440b95800ba0001cd21cd20 }


condition:
	$a0
}