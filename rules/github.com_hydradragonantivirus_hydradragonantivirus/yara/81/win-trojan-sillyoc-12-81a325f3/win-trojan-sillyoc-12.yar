rule Win_Trojan_SillyOC_12
{
strings:
	$a0 = { c7049090b402cd1a88361601b80800f6f680fc007504fe061601be1701bf8e01b97800f2a4 }


condition:
	$a0
}