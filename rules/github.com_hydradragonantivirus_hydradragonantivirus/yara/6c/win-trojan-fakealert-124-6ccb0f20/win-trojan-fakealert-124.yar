rule Win_Trojan_Fakealert_124
{
strings:
	$a0 = { 4572726f724b696c6c657200413439334e }

	$a1 = { 745c416477617265416c657274 }


condition:
	$a0 and $a1
}