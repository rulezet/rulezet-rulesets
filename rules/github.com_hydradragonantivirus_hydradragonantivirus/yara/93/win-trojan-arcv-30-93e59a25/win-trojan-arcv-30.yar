rule Win_Trojan_ARCV_30
{
strings:
	$a0 = { 5e81ee060133c08ed0e844039cd89ec89c9479149c84771499b47b149cd823f45c1500109ec09b9454149b9c56 }


condition:
	$a0
}