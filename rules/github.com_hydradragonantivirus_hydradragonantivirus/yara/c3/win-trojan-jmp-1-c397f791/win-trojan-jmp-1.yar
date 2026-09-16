rule Win_Trojan_Jmp_1
{
strings:
	$a0 = { 0e1fbf3001b3c0b93908b33d8cc8b3b0050000b38550b3c78a05b37d3522b36a8805b3d947b303e2ef9ada2372e9cbb6 }


condition:
	$a0
}