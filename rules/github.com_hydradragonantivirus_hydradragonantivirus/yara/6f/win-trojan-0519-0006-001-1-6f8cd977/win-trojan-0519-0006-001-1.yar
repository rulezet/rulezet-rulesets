rule Win_Trojan__0519_0006_001_1
{
strings:
	$a0 = { 4233c933d2cd21b4408d96cf02b91a00cd21b43ecd21c3b003cfb82435cd215306b4258d96f0 }


condition:
	$a0
}