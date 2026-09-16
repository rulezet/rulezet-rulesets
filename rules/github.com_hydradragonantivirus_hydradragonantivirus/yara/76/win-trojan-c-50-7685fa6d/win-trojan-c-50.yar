rule Win_Trojan_C_50
{
strings:
	$a0 = { 90fa28ccf889293293ea2b876afe0b89e331d5e1e98b3eda02be0301b9e300313c4646e2fac3 }


condition:
	$a0
}