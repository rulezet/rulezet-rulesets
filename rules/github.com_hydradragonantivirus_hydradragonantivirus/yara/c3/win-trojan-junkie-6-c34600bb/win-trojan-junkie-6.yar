rule Win_Trojan_Junkie_6
{
strings:
	$a0 = { b9f401268134????4646e2f7 }


condition:
	$a0
}