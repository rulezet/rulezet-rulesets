rule Win_Trojan_Ufro_1
{
strings:
	$a0 = { c08ed0bc007c89e6501ffb803cfa740383c63e56b9920183c61fe89201a15eb3ff767b45fe5e }


condition:
	$a0
}