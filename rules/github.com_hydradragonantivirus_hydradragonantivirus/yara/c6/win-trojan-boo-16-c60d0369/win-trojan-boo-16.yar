rule Win_Trojan_BOO_16
{
strings:
	$a0 = { 33c0fabc007c8ed0fb33ffbe50618ed881f64365832c048b04c1e006be007c8ec00e1ff3a4 }


condition:
	$a0
}