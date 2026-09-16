rule Win_Trojan_Rape_8
{
strings:
	$a0 = { 140bac5188f1d2c8fec659aae2f4071f58c301 }


condition:
	$a0
}