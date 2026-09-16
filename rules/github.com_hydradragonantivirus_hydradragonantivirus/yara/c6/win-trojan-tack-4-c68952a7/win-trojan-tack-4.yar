rule Win_Trojan_Tack_4
{
strings:
	$a0 = { 50050001a33c02c7063e02ffe0c606400223b4408b1e33 }


condition:
	$a0
}