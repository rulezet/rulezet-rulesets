rule Win_Trojan_Vundo_35
{
strings:
	$a0 = { e44d021350494e }

	$a1 = { 5e83c603812e????????56c300000000000000000000000000 }


condition:
	$a0 and $a1
}