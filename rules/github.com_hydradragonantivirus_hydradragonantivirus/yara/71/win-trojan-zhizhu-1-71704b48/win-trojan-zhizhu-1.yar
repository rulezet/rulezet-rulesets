rule Win_Trojan_Zhizhu_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833decb4001000eb2683fe01740583fe027522a118870010 }


condition:
	$a0
}