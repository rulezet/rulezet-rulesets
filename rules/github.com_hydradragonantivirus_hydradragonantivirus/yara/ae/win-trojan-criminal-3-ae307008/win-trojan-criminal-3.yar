rule Win_Trojan_Criminal_3
{
strings:
	$a0 = { 1900ba530301eae82700cd21e83b00 }


condition:
	$a0
}