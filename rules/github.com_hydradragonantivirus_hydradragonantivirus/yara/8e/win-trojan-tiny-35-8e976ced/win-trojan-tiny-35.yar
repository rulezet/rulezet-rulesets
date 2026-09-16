rule Win_Trojan_Tiny_35
{
strings:
	$a0 = { 4dae7415b002e81e00b185cd69b8 }


condition:
	$a0
}