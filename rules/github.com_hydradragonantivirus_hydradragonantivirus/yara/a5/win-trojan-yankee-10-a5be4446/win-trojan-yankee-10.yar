rule Win_Trojan_Yankee_10
{
strings:
	$a0 = { 1900baed0a9cff1eed0153eb01f95bc3b800428b0ee9018b16e70183ea05730383e901cd21 }


condition:
	$a0
}