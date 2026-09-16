rule Win_Trojan_Fichv2_1
{
strings:
	$a0 = { 0325ba5501cd21b83101ba3a0090b9 }


condition:
	$a0
}