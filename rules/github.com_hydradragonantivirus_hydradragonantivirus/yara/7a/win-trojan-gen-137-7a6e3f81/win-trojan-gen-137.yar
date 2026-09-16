rule Win_Trojan_Gen_137
{
strings:
	$a0 = { e8ff00b43fb9b903bad504cd212ac0e8 }


condition:
	$a0
}