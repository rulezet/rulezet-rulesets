rule Win_Trojan_SillyC_115
{
strings:
	$a0 = { ffb90f00fcf3a674b6b80242e858002e81363efe9619b440ba3efeb9e100cd217212b80042e8 }


condition:
	$a0
}