rule Win_Trojan_IndepDay_1
{
strings:
	$a0 = { ba0201cd215ab408cd213c59740f3c79740b52baaa01b409cd215aeb0952bad601b409cd215a52baf201b409cd }


condition:
	$a0
}