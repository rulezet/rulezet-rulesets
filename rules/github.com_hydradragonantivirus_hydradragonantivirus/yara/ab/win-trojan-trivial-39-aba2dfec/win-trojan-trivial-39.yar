rule Win_Trojan_Trivial_39
{
strings:
	$a0 = { 2000ba9e00cd21eb09b44fcd21721de8eaffb8023dba9e00cd2193b440b965008b160001cd21b4 }


condition:
	$a0
}