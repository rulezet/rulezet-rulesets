rule Win_Trojan_Gotcha_7
{
strings:
	$a0 = { 0612008bc30500018bf0bf0001b9dc02f3a4ba3901061fb82125cd21071fc3474f54434841 }


condition:
	$a0
}