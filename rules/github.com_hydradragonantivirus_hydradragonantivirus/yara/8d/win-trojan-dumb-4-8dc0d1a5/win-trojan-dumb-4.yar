rule Win_Trojan_Dumb_4
{
strings:
	$a0 = { 03008986de0132c0e888ffb440b903008d96dd01cd21b002e878ffb440b9da008d960401cd21b8 }


condition:
	$a0
}