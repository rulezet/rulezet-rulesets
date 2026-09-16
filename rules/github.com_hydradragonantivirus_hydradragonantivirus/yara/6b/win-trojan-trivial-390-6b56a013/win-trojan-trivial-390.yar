rule Win_Trojan_Trivial_390
{
strings:
	$a0 = { 721bb8023dba9e00cd2193b440ba0001 }


condition:
	$a0
}