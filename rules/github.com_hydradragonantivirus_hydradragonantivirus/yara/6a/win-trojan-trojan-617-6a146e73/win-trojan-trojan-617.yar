rule Win_Trojan_Trojan_617
{
strings:
	$a0 = { b43b[0-8]cd21 }

	$a1 = { 2a2e45584500[0-250]2e2e00 }


condition:
	$a0 and $a1
}