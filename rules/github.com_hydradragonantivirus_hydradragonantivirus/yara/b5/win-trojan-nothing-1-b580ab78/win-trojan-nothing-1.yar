rule Win_Trojan_Nothing_1
{
strings:
	$a0 = { 8400b80098a386001fb40fcd2107 }


condition:
	$a0
}