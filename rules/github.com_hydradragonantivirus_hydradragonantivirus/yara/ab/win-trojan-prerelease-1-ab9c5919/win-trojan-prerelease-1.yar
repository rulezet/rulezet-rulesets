rule Win_Trojan_Prerelease_1
{
strings:
	$a0 = { 88450233c08ed8bb13048b073d76027451b876028907 }


condition:
	$a0
}