rule Win_Trojan_VGEN_196
{
strings:
	$a0 = { 0400cc8d868903f6d1fafbf6d1ffd03d24b080460048210d9e3d0305c185883bb7868c03b586fa72dc72dc7e8d1390 }


condition:
	$a0
}