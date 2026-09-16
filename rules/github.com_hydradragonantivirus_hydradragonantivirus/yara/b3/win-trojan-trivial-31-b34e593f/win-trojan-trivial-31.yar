rule Win_Trojan_Trivial_31
{
strings:
	$a0 = { b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b13e9090ba0001cd21 }


condition:
	$a0
}