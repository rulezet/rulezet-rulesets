rule Win_Trojan_Phantom_1
{
strings:
	$a0 = { 0190e800005e56ba4c0881ea000183ee }


condition:
	$a0
}