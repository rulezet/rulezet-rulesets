rule Win_Trojan_Nursteal_1
{
strings:
	$a0 = { 736c6f746e616d653d }

	$a1 = { 48656c6c6f576f726c6442484f }


condition:
	$a0 and $a1
}