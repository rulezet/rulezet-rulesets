rule Win_Trojan_VS_4
{
strings:
	$a0 = { b9f00690b440e8f9025a5872cf813e9e074d5a740ec7069e07e9002d0300a39f07eb3a5052 }


condition:
	$a0
}