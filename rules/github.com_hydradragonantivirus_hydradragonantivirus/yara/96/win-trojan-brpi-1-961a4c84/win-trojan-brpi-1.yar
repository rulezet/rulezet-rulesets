rule Win_Trojan_BrPI_1
{
strings:
	$a0 = { 8916e503b000e8ebfeb440b91800bae303cd50b002e8dcfe0e1fb440b9ff01ba0002cd505a }


condition:
	$a0
}