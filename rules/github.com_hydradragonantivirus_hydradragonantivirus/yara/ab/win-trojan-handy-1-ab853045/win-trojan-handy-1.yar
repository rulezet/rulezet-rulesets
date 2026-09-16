rule Win_Trojan_Handy_1
{
strings:
	$a0 = { 8b1e0901b80042cd217211ba00002e8b0e07012e8b1e0901b440cd212e8b1e0901b43ecd21eb00 }


condition:
	$a0
}