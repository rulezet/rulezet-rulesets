rule Win_Trojan_Sentinel_7
{
strings:
	$a0 = { e816feb8f90f8bd08b46f22bc28946f2 }


condition:
	$a0
}