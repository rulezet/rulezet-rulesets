rule Win_Trojan_Debilas_1
{
strings:
	$a0 = { 8b1e02002e8b0e04002e8b1606002e8b1e080003c303d803cb03d133d2e8e60083ee2181fe00f07203e9c000562e80 }


condition:
	$a0
}