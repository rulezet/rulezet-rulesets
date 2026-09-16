rule Win_Trojan_VB_1698
{
strings:
	$a0 = { 7069746961626c790001001000886f400000000000ffffffffffffffff00000000dc72 }


condition:
	$a0
}