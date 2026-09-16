rule Win_Trojan_Trojan_198
{
strings:
	$a0 = { 95bb000143031f8bfb33 }


condition:
	$a0
}