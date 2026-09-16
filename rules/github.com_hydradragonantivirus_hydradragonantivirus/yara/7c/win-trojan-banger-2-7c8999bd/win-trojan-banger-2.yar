rule Win_Trojan_Banger_2
{
strings:
	$a0 = { da91e8000010ec39d0eab4330030ea6676a4e8000010eb6396f5b955003047da7115e8000010 }


condition:
	$a0
}