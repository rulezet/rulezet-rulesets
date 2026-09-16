rule Win_Trojan__1487_0006_001_1
{
strings:
	$a0 = { 15b440b90300290ea202baa1029c2eff1e9d028b16a9028b0ea702b801579c2eff1e9d02b43e9c }


condition:
	$a0
}