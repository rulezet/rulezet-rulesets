rule Win_Trojan_SillyBP_3
{
strings:
	$a0 = { a38203c7064c00a3008c0e4e0033c951538ec1b801022e8b0e4b012e8a364d0132d2cde0cb }


condition:
	$a0
}