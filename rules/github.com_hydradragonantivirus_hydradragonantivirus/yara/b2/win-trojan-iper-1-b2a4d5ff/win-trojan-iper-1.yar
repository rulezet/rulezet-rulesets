rule Win_Trojan_Iper_1
{
strings:
	$a0 = { c026803e150455740926c606150455eb3a90b81335 }


condition:
	$a0
}