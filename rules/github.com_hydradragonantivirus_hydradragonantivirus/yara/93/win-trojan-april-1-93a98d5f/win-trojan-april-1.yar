rule Win_Trojan_April_1
{
strings:
	$a0 = { fc4d5a751d1f2e8b84bbfc2e8b9cb9 }


condition:
	$a0
}