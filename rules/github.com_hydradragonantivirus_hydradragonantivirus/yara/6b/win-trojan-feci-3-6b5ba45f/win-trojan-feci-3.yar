rule Win_Trojan_Feci_3
{
strings:
	$a0 = { 291cbbc921eb03ff1afe1904b92f8b56fecd265abfdb817efee80375eae3f809b002e4f80e }


condition:
	$a0
}