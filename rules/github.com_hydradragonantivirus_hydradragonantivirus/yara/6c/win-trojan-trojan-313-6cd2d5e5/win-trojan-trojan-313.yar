rule Win_Trojan_Trojan_313
{
strings:
	$a0 = { 5050b019509a8201bc009ac201bc00bf8c061e57bf75090e5731c0509acc071e019a4f071e019a }


condition:
	$a0
}