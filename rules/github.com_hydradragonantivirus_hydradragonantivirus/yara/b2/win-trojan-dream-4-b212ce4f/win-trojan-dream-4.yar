rule Win_Trojan_Dream_4
{
strings:
	$a0 = { b90001f3a5ea6a01e007cd13b801022e8b0e08002e8b160a00cd13a14c002ea32c00a14e00 }


condition:
	$a0
}