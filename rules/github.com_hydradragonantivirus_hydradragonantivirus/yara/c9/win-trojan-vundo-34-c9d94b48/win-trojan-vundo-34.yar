rule Win_Trojan_Vundo_34
{
strings:
	$a0 = { 501b000050494e }

	$a1 = { 5e80060756c300000000000000000000000000000000000000 }


condition:
	$a0 and $a1
}