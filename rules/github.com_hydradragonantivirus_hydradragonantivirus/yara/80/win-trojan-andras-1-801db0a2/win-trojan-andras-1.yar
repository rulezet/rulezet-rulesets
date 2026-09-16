rule Win_Trojan_Andras_1
{
strings:
	$a0 = { 2bd56668b5df8bd5665866f7db4081c14ffb2f060bcd40e9 }


condition:
	$a0
}