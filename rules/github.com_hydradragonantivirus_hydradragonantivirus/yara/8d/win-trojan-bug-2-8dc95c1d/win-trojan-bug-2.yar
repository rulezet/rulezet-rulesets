rule Win_Trojan_Bug_2
{
strings:
	$a0 = { 02008bf0bf300103fe8a84dd06b9ad0530053cff7502b0013c007402fec0474983f90075eb }


condition:
	$a0
}