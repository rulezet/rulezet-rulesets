rule Win_Trojan_Enjoy_1
{
strings:
	$a0 = { 028bcf2e30470343e2f983c60859e2da5f5e5b5958 }


condition:
	$a0
}