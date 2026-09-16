rule Win_Trojan_Trivial_425
{
strings:
	$a0 = { c0b44ebac70133c9cd217303e9a500b8013dba9e00cd2193b440b103ba8101cd21b440b90800ba0301cd21bf0002be }


condition:
	$a0
}