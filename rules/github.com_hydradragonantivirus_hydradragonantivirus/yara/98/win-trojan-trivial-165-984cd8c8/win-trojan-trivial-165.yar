rule Win_Trojan_Trivial_165
{
strings:
	$a0 = { 2193ba0001b440cd21c32a2e434f4d }


condition:
	$a0
}