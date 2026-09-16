rule Win_Trojan_Loch_1
{
strings:
	$a0 = { 7374d1b2fbc71517b5122ab5b5332312a2aa3a34a68a5c3da0c2921a2bd45e3ac5056778 }


condition:
	$a0
}