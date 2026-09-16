rule Win_Trojan_USSR_29
{
strings:
	$a0 = { c08ed833c08bf0bf0000bb0001ff }


condition:
	$a0
}