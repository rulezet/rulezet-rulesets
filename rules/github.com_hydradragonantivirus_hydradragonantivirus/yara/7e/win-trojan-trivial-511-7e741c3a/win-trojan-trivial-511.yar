rule Win_Trojan_Trivial_511
{
strings:
	$a0 = { 3a01cd21721db8013dba9e00cd2193b440b94000ba0001cd21b43ecd21b44fcd21ebe1cd20 }


condition:
	$a0
}