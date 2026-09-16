rule Win_Trojan_Small_3531
{
strings:
	$a0 = { e80000000081ea09ae83635a81c2????000092680f01000081e93b2f2cf859606631c0 }


condition:
	$a0
}