rule Win_Trojan_V_103
{
strings:
	$a0 = { 01e83effc3e81dff8b0e0d01e833ffba0001b98103e82affc33d810372733dfdf8776ebafeff }


condition:
	$a0
}