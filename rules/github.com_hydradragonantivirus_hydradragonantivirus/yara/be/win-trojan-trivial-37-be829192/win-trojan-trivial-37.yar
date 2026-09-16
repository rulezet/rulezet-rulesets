rule Win_Trojan_Trivial_37
{
strings:
	$a0 = { 4eba5e01cd21724b833e9a00647240b80043ba9e00cd21b8014350515233c9cd217227b8013dba9e00cd21721d93b8 }


condition:
	$a0
}