rule Win_Trojan_Trojan_258
{
strings:
	$a0 = { b42fcd21899cb3008c84b50007ba1401 }


condition:
	$a0
}