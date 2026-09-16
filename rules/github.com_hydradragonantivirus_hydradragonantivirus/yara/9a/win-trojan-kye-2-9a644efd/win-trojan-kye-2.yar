rule Win_Trojan_Kye_2
{
strings:
	$a0 = { 5920210d0a5589e531c09acd028700bf641c1e57bf661c1e57bf681c1e57bf6a1c1e579a }


condition:
	$a0
}