rule Win_Trojan_VKit_2
{
strings:
	$a0 = { 9de17db428519ace4a8965002b88552e2b8f31a15278a7035c78a23b5878a22b4479037f2aa25878c4c299c1a1f9 }


condition:
	$a0
}