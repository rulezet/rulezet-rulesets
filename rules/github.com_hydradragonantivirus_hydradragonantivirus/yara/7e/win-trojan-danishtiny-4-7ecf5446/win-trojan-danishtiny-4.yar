rule Win_Trojan_DanishTiny_4
{
strings:
	$a0 = { b9dc00d1e973014e8bfead33c3abe2fa5e595b58c3 }


condition:
	$a0
}