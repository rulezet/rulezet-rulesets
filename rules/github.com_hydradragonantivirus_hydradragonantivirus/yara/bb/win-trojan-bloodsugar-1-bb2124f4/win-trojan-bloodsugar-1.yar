rule Win_Trojan_BloodSugar_1
{
strings:
	$a0 = { 81eb23008a278a570189f7fcb90010ac2ac400d4aae2f8 }


condition:
	$a0
}