rule Win_Trojan_Qpa_3
{
strings:
	$a0 = { b303b99a0290b440cd213bc17303e938ffb43ecd217303 }


condition:
	$a0
}