rule Win_Trojan_Trojan_241
{
strings:
	$a0 = { ff8edf813e04004d01742d8cc048832e1304018ed8832e }


condition:
	$a0
}