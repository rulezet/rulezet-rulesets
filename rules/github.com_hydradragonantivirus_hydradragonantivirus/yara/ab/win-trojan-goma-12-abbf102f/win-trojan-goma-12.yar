rule Win_Trojan_Goma_12
{
strings:
	$a0 = { 585a59e81e00b44fe94dffa4a4a4c3a5a4c3b440b90300c3b91a00b43fc3ba8000b41ac3cd }


condition:
	$a0
}