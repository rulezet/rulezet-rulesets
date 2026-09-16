rule Win_Trojan_TheFreak_1
{
strings:
	$a0 = { 5d81ed0901ba00feb41ab90a01cd21b90100bb090199cd264273fbfec0ebf0bf00018db609 }


condition:
	$a0
}