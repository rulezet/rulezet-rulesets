rule Win_Trojan_BOO_1
{
strings:
	$a0 = { 50fcf3a4cb992bdbcd13b80f0584066c04750341cd13b280520e1fb408cd138875c883e13f }


condition:
	$a0
}