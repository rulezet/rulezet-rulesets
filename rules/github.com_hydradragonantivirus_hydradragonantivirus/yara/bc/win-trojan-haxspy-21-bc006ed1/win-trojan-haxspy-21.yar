rule Win_Trojan_Haxspy_21
{
strings:
	$a0 = { 844f206c697665640c2f841942125da402983bfb736f70686f0e696b255c227bcbc60d20e7f90216c086122e6db4 }


condition:
	$a0
}