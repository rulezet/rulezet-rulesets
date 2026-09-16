rule Win_Trojan_Enola_2
{
strings:
	$a0 = { 74081f8ed8b8000150c38cc80510008bd02e03160801be }


condition:
	$a0
}