rule Win_Trojan_Syslock_1
{
strings:
	$a0 = { e18ac13306140031044646e2f25e59 }


condition:
	$a0
}