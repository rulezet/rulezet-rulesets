rule Win_Trojan_RussianMirror_2
{
strings:
	$a0 = { 9dff80fc4b7403e9c4002efe0e6400 }


condition:
	$a0
}