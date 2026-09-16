rule Win_Trojan_Arara_3
{
strings:
	$a0 = { 6d82f9badd77fcba7dd3b2db23dd2351dba86323527a2efbf9231c1b6864330dccb2d33b9655442b0dbfbefaa9a824 }


condition:
	$a0
}