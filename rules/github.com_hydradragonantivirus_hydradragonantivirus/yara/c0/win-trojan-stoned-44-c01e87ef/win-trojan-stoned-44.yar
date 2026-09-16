rule Win_Trojan_Stoned_44
{
strings:
	$a0 = { 02bf0b00fcf3a4b13cbe8201bf8203f3a774dbbf0103e8160072d38bc7 }


condition:
	$a0
}