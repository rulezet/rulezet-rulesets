rule Win_Trojan_W_377
{
strings:
	$a0 = { 10400081 }

	$a1 = { 75f16800104000c300000000 }


condition:
	$a0 and $a1
}