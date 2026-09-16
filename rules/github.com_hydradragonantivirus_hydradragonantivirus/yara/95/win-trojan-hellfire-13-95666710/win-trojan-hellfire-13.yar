rule Win_Trojan_Hellfire_13
{
strings:
	$a0 = { be030189f7b9????ade90400abe2f9c335????73f7 }


condition:
	$a0
}