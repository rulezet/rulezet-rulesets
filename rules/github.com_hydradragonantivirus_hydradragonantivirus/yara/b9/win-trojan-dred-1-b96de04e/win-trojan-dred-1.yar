rule Win_Trojan_Dred_1
{
strings:
	$a0 = { 57b80200509a24008f00fe0e4323bfec221e579a80008f00e91aff89ec5dc31644726564 }


condition:
	$a0
}