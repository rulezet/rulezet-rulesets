rule Win_Trojan_VGEN_563
{
strings:
	$a0 = { d2b43fcd21c3b43c0e1f33c9cd21c333d2b440cd21c3b80142cd21c3b8024233c999cd21c3 }


condition:
	$a0
}