rule Win_Trojan_Trivial_455
{
strings:
	$a0 = { 0100e9b200e90100e98aeae90100e9b1f3e90100e9cd21 }


condition:
	$a0
}