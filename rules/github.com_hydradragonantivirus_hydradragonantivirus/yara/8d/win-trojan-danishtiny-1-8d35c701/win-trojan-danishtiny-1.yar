rule Win_Trojan_DanishTiny_1
{
strings:
	$a0 = { b90300cd21803de97407b44febdceb6990b80057cd21 }


condition:
	$a0
}