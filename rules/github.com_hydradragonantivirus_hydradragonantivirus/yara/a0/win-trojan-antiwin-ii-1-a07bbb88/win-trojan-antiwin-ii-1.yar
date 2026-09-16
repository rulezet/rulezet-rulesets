rule Win_Trojan_Antiwin_II_1
{
strings:
	$a0 = { 89841408b80a0803c6a304008c0e06009c580d0001509d }


condition:
	$a0
}