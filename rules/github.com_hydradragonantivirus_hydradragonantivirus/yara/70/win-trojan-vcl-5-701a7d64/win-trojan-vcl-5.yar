rule Win_Trojan_Vcl_5
{
strings:
	$a0 = { 8db6????89f7b93301e8[1-7]acc0c004f6d8c0c804f6d032862701f6d0c0c804f6d8c0c004aae2e4c3 }


condition:
	$a0
}