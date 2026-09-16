rule Win_Trojan_Vienna_11
{
strings:
	$a0 = { 8bf283c60a90bf0001b9 }


condition:
	$a0
}