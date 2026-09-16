rule Win_Trojan_AmazonQueen_3
{
strings:
	$a0 = { 81ed03000e1f06b4accd213c30750b2e3b9ed5017d2fb4aecd2133c08ec0bf00028bf5b9ec00f3a58ed9b89e02fa87 }


condition:
	$a0
}