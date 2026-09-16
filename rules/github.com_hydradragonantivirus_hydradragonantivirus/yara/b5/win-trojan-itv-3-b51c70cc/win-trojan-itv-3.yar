rule Win_Trojan_Itv_3
{
strings:
	$a0 = { e800005d81ed48018db61a03bf0001b90300fcf3a406b42fcd21899e24038c862603b41a8d962803cd21b824258d96 }


condition:
	$a0
}