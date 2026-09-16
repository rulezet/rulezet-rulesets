rule Win_Trojan_WereWolf_7
{
strings:
	$a0 = { 2eb83520c1474781ffa20272f3c32ec606a70281ebe7 }


condition:
	$a0
}