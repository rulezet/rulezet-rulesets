rule Win_Trojan_Nygus_4
{
strings:
	$a0 = { 01898e0e01b440b907008d960d01cd21b80242b900008bd1cd21b440b98d018d960601cd21 }


condition:
	$a0
}