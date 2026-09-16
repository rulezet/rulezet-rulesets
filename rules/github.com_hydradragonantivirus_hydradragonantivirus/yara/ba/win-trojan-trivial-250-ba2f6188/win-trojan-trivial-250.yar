rule Win_Trojan_Trivial_250
{
strings:
	$a0 = { b44eba2400cd21721ab8023dba9e00cd21b740 }


condition:
	$a0
}