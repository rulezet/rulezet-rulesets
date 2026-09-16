rule Win_Trojan_VB_1704
{
strings:
	$a0 = { 75666672616765002e2e5c7c7fc3e61203434b98082ba3f11e00373e7ec18119af4f4c }


condition:
	$a0
}