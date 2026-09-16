rule Win_Trojan_Tula_1
{
strings:
	$a0 = { c0bf0400b98c0103cb26890d268c4d021e8ed8be84 }


condition:
	$a0
}