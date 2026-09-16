rule Win_Trojan_SillyC_216
{
strings:
	$a0 = { 01b44eba6c03b9e700cd21e843017347eb33908b3e62 }


condition:
	$a0
}