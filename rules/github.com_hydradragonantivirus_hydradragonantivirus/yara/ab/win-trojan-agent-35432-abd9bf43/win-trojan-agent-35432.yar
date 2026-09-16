rule Win_Trojan_Agent_35432
{
strings:
	$a0 = { 68b26b4b0083e00064ff306489208838c05060 }

	$a1 = { 3dcc725c3d68776142e1b5 }


condition:
	$a0 and $a1
}