rule Win_Trojan_Steppan_1
{
strings:
	$a0 = { bbde0303c32d17012ea3ab00e84f00b4402e8b1ef502b9e002ba1700cd21b43e2e8b1ef5 }


condition:
	$a0
}