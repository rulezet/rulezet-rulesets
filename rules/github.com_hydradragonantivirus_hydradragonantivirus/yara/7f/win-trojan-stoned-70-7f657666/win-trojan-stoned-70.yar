rule Win_Trojan_Stoned_70
{
strings:
	$a0 = { 8000cd1372ac890e070090bebe03bfbe01b92100f3a5b8010333dbfec1cd13eb91 }


condition:
	$a0
}