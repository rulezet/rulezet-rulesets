rule Win_Trojan_Trivial_92
{
strings:
	$a0 = { 2000ba9e00cd21e90900b44fcd21721ce8e9ffb8023dba9e00cd2193b440b96500ba0001cd21b4 }


condition:
	$a0
}