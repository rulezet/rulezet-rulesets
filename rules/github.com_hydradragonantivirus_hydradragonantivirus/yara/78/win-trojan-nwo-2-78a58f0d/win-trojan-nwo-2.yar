rule Win_Trojan_NWO_2
{
strings:
	$a0 = { ba0202b440cd21e8e4002ec6064a0200b440b9420390ba0001cd21b801572e8b1698002e8b }


condition:
	$a0
}