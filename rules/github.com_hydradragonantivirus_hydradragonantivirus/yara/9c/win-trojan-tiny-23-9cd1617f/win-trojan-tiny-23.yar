rule Win_Trojan_Tiny_23
{
strings:
	$a0 = { f3a4a4b426cd21ba4c01b44ecd217301cbb8023dba9e00cd2193b43f8bd68bcccd21803c80 }


condition:
	$a0
}