rule Win_Trojan_SillyOC_2
{
strings:
	$a0 = { b100b44390ba9e00b001cd21b8023dba9e00cd2193b94103b440ba0001cd21b43ecd21ff0646 }


condition:
	$a0
}