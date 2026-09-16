rule Win_Trojan_Globe_2
{
strings:
	$a0 = { 011e57b80100509a6907c6009a9102c600bfd4011e57bfa8041e57b8411f50bfea231e579a54 }


condition:
	$a0
}