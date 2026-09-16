rule Win_Trojan_Gippo_6
{
strings:
	$a0 = { 53511e060e1fb95e0290be3200408b1cba102a0bdaf7d3902114091c404646e2ed }


condition:
	$a0
}