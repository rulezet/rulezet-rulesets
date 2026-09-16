rule Win_Trojan_Italian_12
{
strings:
	$a0 = { 010300558e05000200ffff0000000093010000050000006a08 }


condition:
	$a0
}