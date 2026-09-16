rule Win_Trojan_Mephisto_4
{
strings:
	$a0 = { 01b9b8018bb6850431354747e2fa59c3cd21e8e7ffe9befdb003cf }


condition:
	$a0
}