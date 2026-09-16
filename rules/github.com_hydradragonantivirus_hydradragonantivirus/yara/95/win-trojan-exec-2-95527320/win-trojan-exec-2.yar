rule Win_Trojan_Exec_2
{
strings:
	$a0 = { 1f018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe39302c7860e00ffff8bd633c9b8023c0bff }


condition:
	$a0
}