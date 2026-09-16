rule Win_Trojan_Small_192
{
strings:
	$a0 = { 8ec3bf9002a674134e4fb150f3a4be84005626a526a55fb029abab5f8d7550b9b0fe0e07f3a4c380fc3c7521cdb8 }


condition:
	$a0
}