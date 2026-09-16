rule Win_Trojan_Hellfire_11
{
strings:
	$a0 = { be03018bfeb92b02ade90400abe2f9c335????73f7 }


condition:
	$a0
}