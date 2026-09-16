rule Win_Trojan_Alien_II_1
{
strings:
	$a0 = { 5a003db0fe7716b440b90301cd2133c9b80042cd21b258b104b440cd215a59b80157cd21b43e }


condition:
	$a0
}