rule Win_Trojan_Trivial_507
{
strings:
	$a0 = { 2501b44ecd21e81f00ba1f01b44ecd21e81500b409ba4b01cd21cd202a2e696e69002a2e65786500721db8013d }


condition:
	$a0
}