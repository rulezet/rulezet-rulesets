rule Win_Trojan_Viaggio_1
{
strings:
	$a0 = { 0200eb1051b97d0381e918012ef61547e2fa59c34740b432dec204048aed1671ffbcc5a3a1a1a0 }


condition:
	$a0
}