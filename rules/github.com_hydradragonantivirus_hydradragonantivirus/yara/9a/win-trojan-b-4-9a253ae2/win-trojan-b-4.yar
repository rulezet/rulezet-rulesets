rule Win_Trojan_B_4
{
strings:
	$a0 = { 010350cdd35872c6bebe03bfbe01b92100f3a5412bdb88360600cdd3cb }


condition:
	$a0
}