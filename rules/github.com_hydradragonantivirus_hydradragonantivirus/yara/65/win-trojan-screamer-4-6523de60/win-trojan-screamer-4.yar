rule Win_Trojan_Screamer_4
{
strings:
	$a0 = { 300428d0f6d22e301446fec2e2edc3 }


condition:
	$a0
}