rule Win_Trojan_B_52
{
strings:
	$a0 = { 7cea2f00c007cd12be4c00562e803ef20002740ee8c500bffc01b90200fcf3a5eb03e8be005e }


condition:
	$a0
}