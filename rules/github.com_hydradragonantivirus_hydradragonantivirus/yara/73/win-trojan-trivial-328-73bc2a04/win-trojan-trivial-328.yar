rule Win_Trojan_Trivial_328
{
strings:
	$a0 = { 3801cd21b443b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b13dba0001cd21b43ecd21b44fcd2173d0c3 }


condition:
	$a0
}