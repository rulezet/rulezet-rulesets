rule Win_Trojan_Vgen_16
{
strings:
	$a0 = { 6e004c4c81ed0301b86535cd218cc383fb007579832e0200408cd8488ed8832e03004033c08ed8ff0e1304a113 }


condition:
	$a0
}