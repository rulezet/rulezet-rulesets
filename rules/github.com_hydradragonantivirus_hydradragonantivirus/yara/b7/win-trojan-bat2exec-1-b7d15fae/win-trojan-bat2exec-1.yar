rule Win_Trojan_Bat2Exec_1
{
strings:
	$a0 = { 018b6e008ba602008b9e0400b44acd21a12c0089861a008b9e0000ffe39b04c7861000ffff8bd633c9b8023c0b }


condition:
	$a0
}