rule Win_Trojan_FinnishSprayer_1
{
strings:
	$a0 = { 0333dbcd130e07b8010333dbb90100b600cd135ac3 }


condition:
	$a0
}