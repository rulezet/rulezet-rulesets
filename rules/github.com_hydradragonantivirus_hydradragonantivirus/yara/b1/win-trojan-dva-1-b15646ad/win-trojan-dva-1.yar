rule Win_Trojan_DVA_1
{
strings:
	$a0 = { 8bf281ee0301c35eeb0790eb0490ba00008d94c202b92000b44ecd217342e9bb00b43db0028d94c802cd2189844e }


condition:
	$a0
}