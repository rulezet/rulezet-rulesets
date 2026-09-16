rule Win_Trojan_Heja_2
{
strings:
	$a0 = { 35cd2126817f02602e751d5e83ee0681c61300bf00018cc88ec08ed8b90500fcf3a40eb8000150cbb452cd2183eb }


condition:
	$a0
}