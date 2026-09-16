rule Win_Trojan_Horse_22
{
strings:
	$a0 = { ff3424e8??0?0000a300304000558b6c2404e8??000000 }


condition:
	$a0
}