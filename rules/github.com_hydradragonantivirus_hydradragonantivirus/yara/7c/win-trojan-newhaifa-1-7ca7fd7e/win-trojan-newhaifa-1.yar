rule Win_Trojan_NewHaifa_1
{
strings:
	$a0 = { e0cd2180fce0731580fc037210b4ddbf0001beaa0703f72e8b4d11cd218cc8 }


condition:
	$a0
}