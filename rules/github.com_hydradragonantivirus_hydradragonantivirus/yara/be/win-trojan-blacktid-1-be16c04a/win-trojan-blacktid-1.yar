rule Win_Trojan_BlackTid_1
{
strings:
	$a0 = { f22e8ba626092e8e962809c3fa575533ede8ccffb440b9730933d2bf0000cd219ce8bcff9d }


condition:
	$a0
}