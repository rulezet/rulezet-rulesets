rule Win_Trojan_Trivial_84
{
strings:
	$a0 = { 2000b44eba2201cd21b8023dba9e00cd218bd8b440b94b00ba0001cd212a2e2a00a2e2a212dc10 }


condition:
	$a0
}