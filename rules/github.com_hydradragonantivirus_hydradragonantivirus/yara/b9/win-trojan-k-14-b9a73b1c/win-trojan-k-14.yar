rule Win_Trojan_K_14
{
strings:
	$a0 = { 022ea20001a0c6022ea20101a0c7022ea20201b9000133db2e8a078887c90243e2f6baa902b92000b44ecd21731a }


condition:
	$a0
}