rule Win_Trojan_Brothers_2
{
strings:
	$a0 = { e2fa8bd7c3b440b9fd07ba0001eb4fb8 }


condition:
	$a0
}