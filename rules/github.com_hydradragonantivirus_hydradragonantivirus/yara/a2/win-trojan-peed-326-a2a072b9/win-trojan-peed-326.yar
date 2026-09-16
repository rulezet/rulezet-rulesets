rule Win_Trojan_Peed_326
{
strings:
	$a0 = { 03742430eb6a48b9e1cbffff81c167450000ba20020200c1c20589d6c351eb10 }


condition:
	$a0
}