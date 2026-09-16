rule Win_Trojan_Trivial_330
{
strings:
	$a0 = { 2db8b300b8013dba9e00cd21b740ba000180c6b580eeb593b13dcd21b4ecb43ecd21b4d0b4 }


condition:
	$a0
}