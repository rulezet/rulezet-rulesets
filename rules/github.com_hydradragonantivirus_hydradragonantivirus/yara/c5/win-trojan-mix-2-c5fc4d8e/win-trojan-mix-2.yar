rule Win_Trojan_Mix_2
{
strings:
	$a0 = { 26c6067f03ffb452cd21268b47fe8ec0 }


condition:
	$a0
}