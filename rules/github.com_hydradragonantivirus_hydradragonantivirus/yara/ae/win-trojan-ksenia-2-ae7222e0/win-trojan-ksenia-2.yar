rule Win_Trojan_Ksenia_2
{
strings:
	$a0 = { cd218bec8b6efa81ed05021e6aff1fa007001f342f98408bd08db64f11b9210f2e8a042e00 }


condition:
	$a0
}