rule Win_Trojan_Jerusalem_47
{
strings:
	$a0 = { fc062e8c0631002e8c0639002e8c063d }


condition:
	$a0
}