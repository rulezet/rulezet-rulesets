rule Win_Trojan_Alien_2
{
strings:
	$a0 = { 2ea100003dcd207506e81d00eb03900e1f8b0e200083e9468a1e1d00be74002bce301c46e2fbeb13 }


condition:
	$a0
}