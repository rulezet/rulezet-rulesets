rule Win_Trojan_TIB_1
{
strings:
	$a0 = { fcfe7505bb00029dcf3d004b7403e96701b8023dcd2173 }


condition:
	$a0
}