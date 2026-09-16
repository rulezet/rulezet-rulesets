rule Win_Trojan_Trivial_356
{
strings:
	$a0 = { ca01b9c90090ba0001b440cd21c3b44ebabd0133c9cd217203eb1a90b43bbac101cd21720eeb }


condition:
	$a0
}