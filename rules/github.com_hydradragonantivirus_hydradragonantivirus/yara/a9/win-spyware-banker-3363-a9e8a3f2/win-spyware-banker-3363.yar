rule Win_Spyware_Banker_3363
{
strings:
	$a0 = { ac4a5e7dc3249b3dd759acae877ca3c45c6b7f06686e6ce1becc11f9ae63754608dcf7f82f9e397190d209893c819c644e0a6a627d9a51cc0b4d7f3897cd699b3244702cad2e }


condition:
	$a0
}