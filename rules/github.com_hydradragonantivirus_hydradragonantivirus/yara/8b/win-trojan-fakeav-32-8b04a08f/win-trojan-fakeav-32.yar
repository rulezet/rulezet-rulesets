rule Win_Trojan_Fakeav_32
{
strings:
	$a0 = { 558bece82b0000008b54240cff8aac000000750a8182b8000000020000008b8a }


condition:
	$a0
}