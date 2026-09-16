rule Win_Trojan_VcgKit_based_1
{
strings:
	$a0 = { e8ffce2bf081eeffce5881c6354281c6ffcfcd2181c3012c81c3ffd3b8ffd481c0004f81e8ffd4 }


condition:
	$a0
}