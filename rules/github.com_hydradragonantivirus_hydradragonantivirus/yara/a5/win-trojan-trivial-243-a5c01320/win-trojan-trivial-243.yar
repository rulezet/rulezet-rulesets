rule Win_Trojan_Trivial_243
{
strings:
	$a0 = { b44eeb02b44fcd217301c3b8013dba9e00cd2193b440b12aba0001cd21b43ecd21ebe1 }


condition:
	$a0
}