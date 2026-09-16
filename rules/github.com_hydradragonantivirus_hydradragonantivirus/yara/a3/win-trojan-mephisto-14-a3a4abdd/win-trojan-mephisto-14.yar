rule Win_Trojan_Mephisto_14
{
strings:
	$a0 = { 02e857002d0300a34201b440b9fe01ba0001e872ff33c0e84100b80040b90300ba4101e861ff59 }


condition:
	$a0
}