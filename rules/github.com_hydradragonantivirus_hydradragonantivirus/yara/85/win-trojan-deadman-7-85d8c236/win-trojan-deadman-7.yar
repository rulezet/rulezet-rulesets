rule Win_Trojan_Deadman_7
{
strings:
	$a0 = { b8004233c999cd21b80057cd215152b440b9af03baaf04cd2133c87562b80242b9ffffba51fc }


condition:
	$a0
}