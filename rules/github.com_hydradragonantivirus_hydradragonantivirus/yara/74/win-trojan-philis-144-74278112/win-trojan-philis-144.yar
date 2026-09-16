rule Win_Trojan_Philis_144
{
strings:
	$a0 = { 575f605233d2eb01eb5ae80000000057 }


condition:
	$a0
}