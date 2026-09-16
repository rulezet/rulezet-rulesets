rule Win_Trojan_Maltese_Amoeba_1
{
strings:
	$a0 = { 538ad28bc08bdb1e9ef5060e90070ef81feb009191fcf8bf4700b9a30489fe8ae48ac08bc9ad35ab8cab8ad2f8e2 }


condition:
	$a0
}