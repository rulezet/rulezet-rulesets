rule Win_Trojan_AntiCAD_2
{
strings:
	$a0 = { 8ed8a11304b106d3e08ed833f68b44 }


condition:
	$a0
}