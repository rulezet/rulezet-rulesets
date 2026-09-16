rule Win_Trojan_V_16
{
strings:
	$a0 = { 0500ba5f03b440cd21724133c98bd1b80242cd212e803ea00000750bb9ffffba5df8b80242cd21 }


condition:
	$a0
}