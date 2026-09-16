rule Win_Trojan_Silly_48
{
strings:
	$a0 = { 0e1f89c3474b8cd8eb6c }


condition:
	$a0
}