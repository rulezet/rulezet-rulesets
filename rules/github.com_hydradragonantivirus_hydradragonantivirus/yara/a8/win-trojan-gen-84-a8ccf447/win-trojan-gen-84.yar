rule Win_Trojan_Gen_84
{
strings:
	$a0 = { bf0001578bcc2bcef3a433f633ff33 }


condition:
	$a0
}