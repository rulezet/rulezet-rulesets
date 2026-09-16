rule Win_Trojan_Dir_6
{
strings:
	$a0 = { bc0006ff06eb0433c98ed9c506c10005 }


condition:
	$a0
}