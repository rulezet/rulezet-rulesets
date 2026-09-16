rule Win_Trojan_Synflood_3
{
strings:
	$a0 = { 595964891068c15540008d45dcba04000000e84fe1ffffc3e9c1dbffffebeb5f5e5be82be0ffff000000ffffffff480000000d0a73796e2076312e36205b3134204175672032 }


condition:
	$a0
}