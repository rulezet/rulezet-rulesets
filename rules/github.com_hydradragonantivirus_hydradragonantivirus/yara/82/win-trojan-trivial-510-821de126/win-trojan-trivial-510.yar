rule Win_Trojan_Trivial_510
{
strings:
	$a0 = { c6b9ff00cd217223a09e003c2e7418b8023dba9e00cd2193b440ba0001b9820290cd21b43e }


condition:
	$a0
}