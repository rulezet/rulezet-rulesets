rule Win_Trojan_Fakealert_138
{
strings:
	$a0 = { 558becb9080000006a006a004975f9515356b81c224800e82447f8ff33c05568 }


condition:
	$a0
}