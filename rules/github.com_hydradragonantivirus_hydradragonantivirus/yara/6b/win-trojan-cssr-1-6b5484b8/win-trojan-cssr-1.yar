rule Win_Trojan_CSSR_1
{
strings:
	$a0 = { 03eb25903d0300751f8bde }


condition:
	$a0
}