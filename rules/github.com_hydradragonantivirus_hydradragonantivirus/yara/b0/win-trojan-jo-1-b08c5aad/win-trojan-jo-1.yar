rule Win_Trojan_Jo_1
{
strings:
	$a0 = { f08ec0bf08e0813d434f751b817d }


condition:
	$a0
}