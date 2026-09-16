rule Win_Trojan_Tiny_76
{
strings:
	$a0 = { 43b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b1449090ba0001cd21 }


condition:
	$a0
}