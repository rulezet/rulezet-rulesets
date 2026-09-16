rule Win_Trojan_Trivial_556
{
strings:
	$a0 = { 833e????0074??ac2ac132c1d2c0aaff0e????ebebc3 }


condition:
	$a0
}