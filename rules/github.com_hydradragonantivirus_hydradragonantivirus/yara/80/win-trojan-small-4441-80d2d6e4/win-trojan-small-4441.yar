rule Win_Trojan_Small_4441
{
strings:
	$a0 = { 6853530400b8c7cfbdfff7d089e28902 }


condition:
	$a0
}