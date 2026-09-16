rule Win_Trojan_VGEN_413
{
strings:
	$a0 = { 21b4c5b1103c057204b48bb1148826f502880eb0028b2e020083c5c08ec5be00018bfeb90002fcf3a45606b820 }


condition:
	$a0
}