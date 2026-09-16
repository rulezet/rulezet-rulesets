rule Win_Trojan_Literak_1
{
strings:
	$a0 = { e80000582d05000e50c1e8048cca03c250682900ff6ef83e204c69546552614b2076312e30203c1e06b809c6cd21 }


condition:
	$a0
}