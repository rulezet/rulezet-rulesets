rule Win_Trojan_BOO_12
{
strings:
	$a0 = { 02eb02b4038b163900b106d2e60a3638008bca86e98a163b008a363700cd83c3fa33c08ed88ec0 }


condition:
	$a0
}