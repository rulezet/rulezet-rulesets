rule Win_Trojan_Trivial_148
{
strings:
	$a0 = { 01b44ecd21ba9e00b8013dcd2193b440b91f00ba0001cd21c32a2e }


condition:
	$a0
}