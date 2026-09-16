rule Win_Trojan_Violator_4
{
strings:
	$a0 = { bf0001f3a48bf2b430cd213c007503e9 }


condition:
	$a0
}