rule Win_Trojan_Eddie_2
{
strings:
	$a0 = { d3e8408cd103c18cd9498ec1bf0200ba }


condition:
	$a0
}