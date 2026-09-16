rule Win_Trojan_Rotgrub_2
{
strings:
	$a0 = { b91900a4e2fdbadc02ffd2c353bac902ffd25bb440b9dc01ba0001cd2153bac902ffd25bc3 }


condition:
	$a0
}