rule Win_Trojan_Doomsday_3
{
strings:
	$a0 = { 0301b9d102bef6048bd92800e2fa69d681f6b0b410101010dcaaaee3efed80dcb1b0b0b0c3aec3cfcd8080d9f5c1a0 }


condition:
	$a0
}