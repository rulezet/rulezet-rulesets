rule Win_Trojan_Peed_399
{
strings:
	$a0 = { f8e8bd0000005589e5890189d88b5d086bdb0343c9c20400f7da291424c389daf7da01d0ba4e00000083f80074eac3bf }


condition:
	$a0
}