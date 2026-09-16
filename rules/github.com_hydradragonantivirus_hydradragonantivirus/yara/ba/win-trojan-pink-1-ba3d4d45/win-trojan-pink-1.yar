rule Win_Trojan_Pink_1
{
strings:
	$a0 = { 5352aed13cd14dd9f1c8495655655c2f7541403f6c5e91a4a05a89a1a5a1558494a0a59894a04d }


condition:
	$a0
}