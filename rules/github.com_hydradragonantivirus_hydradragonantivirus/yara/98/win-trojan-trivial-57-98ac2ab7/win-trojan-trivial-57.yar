rule Win_Trojan_Trivial_57
{
strings:
	$a0 = { 4eb120ba3001cd21b8013dba9e00cd2193b440b97900ba0001cd21b409ba3401cd21ba6201cd21b44f8826 }


condition:
	$a0
}