rule Win_Trojan_N_13
{
strings:
	$a0 = { 96ff028db60900b9650131144646e2fac3e800005d81ed1f03eb00c3 }


condition:
	$a0
}