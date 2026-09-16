rule Win_Trojan_Stoned_49
{
strings:
	$a0 = { 03bb0002b90f00ba8000cd1372dfbebe03bfbe01b94202f3a4b8010333dbfec1cd13 }


condition:
	$a0
}