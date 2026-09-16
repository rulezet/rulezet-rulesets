rule Win_Trojan_SpanishTelecom_1
{
strings:
	$a0 = { eb150e1fbb3c7c8b0735ffff8907434381fb5a7d72f1c3 }


condition:
	$a0
}