rule Win_Trojan_Small_4287
{
strings:
	$a0 = { 60e8[0-255]8d44242c8b44200083f801[0-255]8d5c24 }


condition:
	$a0
}