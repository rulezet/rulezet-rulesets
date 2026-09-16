rule Win_Trojan_Perth_1
{
strings:
	$a0 = { 1e07eb010ee80f00eb0134e80b00eb010fe80e00e2efc3acc3eb01f1eb01ab34fac3eb06e8aaeb0403e8ebf9c3 }


condition:
	$a0
}