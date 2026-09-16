rule Win_Trojan_Peed_375
{
strings:
	$a0 = { 81c78104000081ff81040000741f81ff0dd000007f17b9 }


condition:
	$a0
}