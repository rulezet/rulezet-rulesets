rule Win_Trojan_Sov_1
{
strings:
	$a0 = { 33c0aaba4a02b8023dcd217303eb71 }


condition:
	$a0
}