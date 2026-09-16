rule Win_Trojan_Syslock_2
{
strings:
	$a0 = { 8ae18ac13306140031044646e2f2 }


condition:
	$a0
}