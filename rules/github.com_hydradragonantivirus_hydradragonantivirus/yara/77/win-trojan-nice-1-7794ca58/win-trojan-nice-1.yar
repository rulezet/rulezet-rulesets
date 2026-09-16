rule Win_Trojan_Nice_1
{
strings:
	$a0 = { c08ed0bc007c161fe800005e83c61056b4d6b9a001302446e2fbc3 }


condition:
	$a0
}