rule Win_Trojan_Mephisto_2
{
strings:
	$a0 = { 01b9ad018bb66e0431354747e2fa59c3cd21e8e7ffe9c9fdb003cf }


condition:
	$a0
}