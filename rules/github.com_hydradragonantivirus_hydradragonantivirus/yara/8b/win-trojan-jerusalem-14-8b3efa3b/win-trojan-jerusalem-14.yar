rule Win_Trojan_Jerusalem_14
{
strings:
	$a0 = { 42cd21720933d2b91007b440cd21 }


condition:
	$a0
}