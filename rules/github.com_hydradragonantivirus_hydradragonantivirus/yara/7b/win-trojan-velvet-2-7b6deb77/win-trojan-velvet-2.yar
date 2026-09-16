rule Win_Trojan_Velvet_2
{
strings:
	$a0 = { d2cd21b440ba0001b9d007cd21b8024233c933d2cd21b440b9d00733d21e8eddcd211fb43ecd21 }


condition:
	$a0
}