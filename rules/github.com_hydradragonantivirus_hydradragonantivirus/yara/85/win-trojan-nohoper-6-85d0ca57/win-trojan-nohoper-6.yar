rule Win_Trojan_Nohoper_6
{
strings:
	$a0 = { 609ce8060000000000cf5905005d81ed5a214000555f83c7014f7423b9f77c }


condition:
	$a0
}