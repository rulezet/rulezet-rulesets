rule Win_Trojan_F_4
{
strings:
	$a0 = { 2a04bf2a045733f681c50001e8f601b440b939055acd21b80042e84000b440b90400ba6503cd21 }


condition:
	$a0
}