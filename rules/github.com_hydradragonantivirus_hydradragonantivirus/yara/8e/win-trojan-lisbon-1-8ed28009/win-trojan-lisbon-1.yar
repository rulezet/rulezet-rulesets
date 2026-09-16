rule Win_Trojan_Lisbon_1
{
strings:
	$a0 = { b9880289f281eaf901cd21721f3d }


condition:
	$a0
}