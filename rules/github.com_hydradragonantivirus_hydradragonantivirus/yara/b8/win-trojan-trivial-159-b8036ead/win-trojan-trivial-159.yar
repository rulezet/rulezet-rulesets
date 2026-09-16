rule Win_Trojan_Trivial_159
{
strings:
	$a0 = { 20ba1d01cd21b8023dba9e00cd2193b440ba0001cd21b44fe2e5 }


condition:
	$a0
}