rule Win_Trojan_Trivial_30
{
strings:
	$a0 = { b443b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b13eba0001cd21b43e }


condition:
	$a0
}