rule Win_Trojan_HCarry_1
{
strings:
	$a0 = { 180189f7b93a03e80400e90a0000ac32060e01aae2f8c3 }


condition:
	$a0
}