rule Win_Trojan_Trivial_280
{
strings:
	$a0 = { b44ecd21721db8023dba9e00cd21720f93b92d00ba0001b440cd21b43ecd21b44febdfc3 }


condition:
	$a0
}