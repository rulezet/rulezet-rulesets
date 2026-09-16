rule Win_Trojan_Dennis_1
{
strings:
	$a0 = { 03a39400e8ab00b002e89c00b440b9e80333d2e8a300b801578b0eeb038b16ed03e89500b43e }


condition:
	$a0
}