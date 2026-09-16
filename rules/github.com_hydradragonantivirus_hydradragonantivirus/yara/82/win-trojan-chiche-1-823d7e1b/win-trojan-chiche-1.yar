rule Win_Trojan_Chiche_1
{
strings:
	$a0 = { 8b2d83ed0783c4021e060e0e1f078db62900b973058034 }


condition:
	$a0
}