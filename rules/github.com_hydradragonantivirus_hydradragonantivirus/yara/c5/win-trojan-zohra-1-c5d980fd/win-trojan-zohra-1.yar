rule Win_Trojan_Zohra_1
{
strings:
	$a0 = { e401741a2401740c26c705b41926c74502cd21c326c70581eb26897502c32401740a26c705 }


condition:
	$a0
}