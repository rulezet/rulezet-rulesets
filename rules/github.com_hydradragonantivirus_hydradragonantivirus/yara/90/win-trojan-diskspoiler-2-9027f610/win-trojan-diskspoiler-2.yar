rule Win_Trojan_Diskspoiler_2
{
strings:
	$a0 = { e800005e8bfeb90b0580750eff9047e2 }


condition:
	$a0
}