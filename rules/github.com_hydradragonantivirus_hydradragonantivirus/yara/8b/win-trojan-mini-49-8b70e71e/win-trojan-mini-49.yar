rule Win_Trojan_Mini_49
{
strings:
	$a0 = { 03018bfe8a269d02b98901ac32c4aae2fac3 }


condition:
	$a0
}