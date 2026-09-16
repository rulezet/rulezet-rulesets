rule Win_Trojan_Trivial_168
{
strings:
	$a0 = { 4eba2601cd217223b8023dba9e00cd21720f93b440ba0001b95601cd21b43ecd21b44febdf }


condition:
	$a0
}