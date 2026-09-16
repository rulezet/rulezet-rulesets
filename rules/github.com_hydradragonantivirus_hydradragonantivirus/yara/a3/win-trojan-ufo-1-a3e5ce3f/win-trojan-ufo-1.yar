rule Win_Trojan_UFO_1
{
strings:
	$a0 = { 07572e30060600bf0300b92201268a2532e02e8826e3055051b440b901000e1fbae305cd215958 }


condition:
	$a0
}