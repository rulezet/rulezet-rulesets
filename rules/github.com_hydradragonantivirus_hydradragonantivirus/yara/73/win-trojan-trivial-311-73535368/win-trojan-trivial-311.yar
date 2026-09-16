rule Win_Trojan_Trivial_311
{
strings:
	$a0 = { 54b44eba320180c7cb80efcbcd21b82600b8023dba9e00cd21b7b5b74093ba0201b13481c3da0081ebda00cd21e90000c3 }


condition:
	$a0
}