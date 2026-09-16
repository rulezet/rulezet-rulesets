rule Win_Trojan_Kitiara_1
{
strings:
	$a0 = { 2002cd27b001eb0c90b000eb0390b0022bd22bc9b442cd21c3b440cd21c3ba0202b409cd21 }


condition:
	$a0
}