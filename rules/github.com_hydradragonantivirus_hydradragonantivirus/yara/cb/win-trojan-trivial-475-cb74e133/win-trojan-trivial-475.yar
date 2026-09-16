rule Win_Trojan_Trivial_475
{
strings:
	$a0 = { 21e80f00b409ba4c01cd21b8004ccd21e91d00b8013dba9e00cd2193b440b16fba0001cd21b43e }


condition:
	$a0
}