rule Win_Trojan_Hero_3
{
strings:
	$a0 = { 8a0133c0bf0002030583c702e2f929 }


condition:
	$a0
}