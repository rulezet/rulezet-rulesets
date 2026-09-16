rule Win_Trojan_Horse_2
{
strings:
	$a0 = { 2012e87402268a1db81612e86b025b83c711 }


condition:
	$a0
}