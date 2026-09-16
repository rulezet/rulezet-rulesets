rule Win_Trojan_AT_11
{
strings:
	$a0 = { c0a20b008ed8b052a34c008c0e4e00ea0000c007 }


condition:
	$a0
}