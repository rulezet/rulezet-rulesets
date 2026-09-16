rule Win_Trojan_Fakealert_123
{
strings:
	$a0 = { 5745425f4d4f4e49544f525f4636334339 }

	$a1 = { 5c5765624d6f6e69746f722e706462 }


condition:
	$a0 and $a1
}