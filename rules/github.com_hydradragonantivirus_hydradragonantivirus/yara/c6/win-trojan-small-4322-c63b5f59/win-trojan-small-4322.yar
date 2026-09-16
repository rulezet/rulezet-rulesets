rule Win_Trojan_Small_4322
{
strings:
	$a0 = { 60e85b0000005050e83d000000e8780000008d2d }


condition:
	$a0
}