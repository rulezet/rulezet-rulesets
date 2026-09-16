rule Win_Trojan_Antimit_1
{
strings:
	$a0 = { 8a260701eb1290ac32c4aae2fab419cd218af0b40e }


condition:
	$a0
}