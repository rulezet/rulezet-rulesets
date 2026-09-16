rule Win_Trojan_Jerusalem_52
{
strings:
	$a0 = { 062202cb580510008ec00e1fb9 }


condition:
	$a0
}