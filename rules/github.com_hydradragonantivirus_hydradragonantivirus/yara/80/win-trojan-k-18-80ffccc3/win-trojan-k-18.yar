rule Win_Trojan_K_18
{
strings:
	$a0 = { 02b80042cd217253b9ca00be7501a0eb02300446e2fbba2001b9cd01908b1ee202b440cd21 }


condition:
	$a0
}