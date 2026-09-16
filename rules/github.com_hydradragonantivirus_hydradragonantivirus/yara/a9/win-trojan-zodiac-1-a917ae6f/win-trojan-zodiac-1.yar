rule Win_Trojan_Zodiac_1
{
strings:
	$a0 = { b801287326803eb7010977e6b403b009bb03018a2eb8018a0eb701b600b202cd13fe06b701eb }


condition:
	$a0
}