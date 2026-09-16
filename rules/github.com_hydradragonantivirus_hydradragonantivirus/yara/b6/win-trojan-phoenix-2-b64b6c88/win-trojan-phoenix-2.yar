rule Win_Trojan_Phoenix_2
{
strings:
	$a0 = { 3d8bf733d2b854025033552247474879f8593154224646497df8 }


condition:
	$a0
}