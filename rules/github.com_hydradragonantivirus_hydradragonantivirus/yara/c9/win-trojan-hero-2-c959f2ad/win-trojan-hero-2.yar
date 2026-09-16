rule Win_Trojan_Hero_2
{
strings:
	$a0 = { 33c0bf0002030583c702e2f929069c03b8004233c9 }


condition:
	$a0
}