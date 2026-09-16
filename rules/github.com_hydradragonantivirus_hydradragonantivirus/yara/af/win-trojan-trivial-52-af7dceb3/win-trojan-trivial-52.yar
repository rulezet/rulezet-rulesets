rule Win_Trojan_Trivial_52
{
strings:
	$a0 = { be12018bfeb15bac3457aafec980f9ff75f5e31907e37b9a76df415e56e94556e8 }


condition:
	$a0
}