rule Win_Trojan_Mailbomber_3
{
strings:
	$a0 = { 558bec83c4ec5333c08945ec33c05568 }

	$a1 = { 4a756d7049442822 }

	$a2 = { 544d61696c426f6d626572 }


condition:
	$a0 and $a1 and $a2
}