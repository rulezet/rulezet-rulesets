rule Win_Trojan_Tiny_79
{
strings:
	$a0 = { 408d94ab01b90200cd21b43ecd21ffe5 }


condition:
	$a0
}