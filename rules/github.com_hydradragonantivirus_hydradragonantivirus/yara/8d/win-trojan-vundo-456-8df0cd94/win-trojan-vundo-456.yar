rule Win_Trojan_Vundo_456
{
strings:
	$a0 = { 50eb1151484b4a505552544a4b4d564c4d49534ce9f9 }


condition:
	$a0
}