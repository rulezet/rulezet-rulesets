rule Win_Trojan_Star_Dot_2
{
strings:
	$a0 = { 268b1e6c04891e720407 }


condition:
	$a0
}