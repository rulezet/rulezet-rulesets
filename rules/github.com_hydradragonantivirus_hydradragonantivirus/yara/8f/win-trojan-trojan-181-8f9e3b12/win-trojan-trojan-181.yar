rule Win_Trojan_Trojan_181
{
strings:
	$a0 = { 0e1fb95206fcf3a406b8880050cb2ec6 }


condition:
	$a0
}