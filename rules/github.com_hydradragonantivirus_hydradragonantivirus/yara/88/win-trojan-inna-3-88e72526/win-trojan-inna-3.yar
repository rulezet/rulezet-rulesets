rule Win_Trojan_Inna_3
{
strings:
	$a0 = { 011e578b7e04368b459e368b55a02d080083da0052509a2b08c100bf72011e57bfd2371e57b8 }


condition:
	$a0
}