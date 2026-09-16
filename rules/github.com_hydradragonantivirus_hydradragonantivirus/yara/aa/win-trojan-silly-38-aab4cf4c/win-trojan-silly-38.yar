rule Win_Trojan_Silly_38
{
strings:
	$a0 = { 1f89c3474b8cd8eb6c8cd80b7e817f }


condition:
	$a0
}