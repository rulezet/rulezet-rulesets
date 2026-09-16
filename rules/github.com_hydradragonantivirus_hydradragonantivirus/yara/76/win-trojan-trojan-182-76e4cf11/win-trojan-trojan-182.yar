rule Win_Trojan_Trojan_182
{
strings:
	$a0 = { 1fb96406fcf3a406b89c0050cb2ec6 }


condition:
	$a0
}