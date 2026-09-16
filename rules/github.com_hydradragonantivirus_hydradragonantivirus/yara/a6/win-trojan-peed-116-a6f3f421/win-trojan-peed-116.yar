rule Win_Trojan_Peed_116
{
strings:
	$a0 = { e80000000058e81500000089daf7da01 }


condition:
	$a0
}