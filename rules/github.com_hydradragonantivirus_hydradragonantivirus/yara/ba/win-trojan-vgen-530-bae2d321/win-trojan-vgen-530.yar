rule Win_Trojan_VGEN_530
{
strings:
	$a0 = { f281ee0301c35eeb0790eb0490ba00008d94c802b92000b44ecd217342e9c300b43db0028d94ce02cd21898456 }


condition:
	$a0
}