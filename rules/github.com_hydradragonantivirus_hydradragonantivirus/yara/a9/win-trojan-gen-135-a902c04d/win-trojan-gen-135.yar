rule Win_Trojan_Gen_135
{
strings:
	$a0 = { 0303b440b90300ba1603cd21c38b1e0803b8 }


condition:
	$a0
}