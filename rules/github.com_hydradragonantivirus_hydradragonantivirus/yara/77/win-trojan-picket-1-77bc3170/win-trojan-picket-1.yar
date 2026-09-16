rule Win_Trojan_Picket_1
{
strings:
	$a0 = { 50535152565755061e8bf4368b6c148b6efe83c50336c744140001b9de038db62c018bfead351a1aabe2f9f1628a17 }


condition:
	$a0
}