rule Win_Trojan_Sandra_1
{
strings:
	$a0 = { fabb????f8fa8a27903226????fb8827fa8a6702fb3226????f98867029083c301fb81fb7708fb7edc }


condition:
	$a0
}