rule Win_Trojan_Alien_II_3
{
strings:
	$a0 = { cd212ea35a003d0a00721b3d20fd7716b440b93001cd2133c9b80042cd21b258b104b440cd21 }


condition:
	$a0
}