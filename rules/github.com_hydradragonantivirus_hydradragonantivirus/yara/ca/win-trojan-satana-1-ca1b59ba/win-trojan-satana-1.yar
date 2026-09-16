rule Win_Trojan_Satana_1
{
strings:
	$a0 = { 3e54024d5a7451c6065402e92d0300a35502b8004233c933d2e86500b440b91800ba5402e85a00 }


condition:
	$a0
}