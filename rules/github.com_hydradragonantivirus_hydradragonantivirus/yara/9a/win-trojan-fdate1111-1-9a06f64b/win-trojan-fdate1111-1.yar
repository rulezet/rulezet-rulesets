rule Win_Trojan_Fdate1111_1
{
strings:
	$a0 = { 07bb15002e8037314381fb3a027cf5 }


condition:
	$a0
}