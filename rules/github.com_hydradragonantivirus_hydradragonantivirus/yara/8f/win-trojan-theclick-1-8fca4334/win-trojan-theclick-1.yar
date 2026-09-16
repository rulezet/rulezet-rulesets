rule Win_Trojan_TheClick_1
{
strings:
	$a0 = { 3dcd21722089851500b43f8d9512008b9d1500b90300 }


condition:
	$a0
}