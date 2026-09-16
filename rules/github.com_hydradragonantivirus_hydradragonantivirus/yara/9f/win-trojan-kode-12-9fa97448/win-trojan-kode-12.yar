rule Win_Trojan_Kode_12
{
strings:
	$a0 = { 4eba2d01cd21b8013dba9e00cd21ba00018bd8b15ab440cd21b43ecd21b44fcd2173e3 }


condition:
	$a0
}