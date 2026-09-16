rule Win_Trojan_Aniav_1
{
strings:
	$a0 = { b99404ba0001b440e85400722633d233c9b80042e84800721ab90300ba8605b440e83b0072 }


condition:
	$a0
}