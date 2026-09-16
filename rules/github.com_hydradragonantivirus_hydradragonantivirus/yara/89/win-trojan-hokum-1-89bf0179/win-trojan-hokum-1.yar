rule Win_Trojan_Hokum_1
{
strings:
	$a0 = { 40636f7079202a2e626174202b2046524f472d342e686f6b202a2e686f74203e6e756c }


condition:
	$a0
}