rule Win_Trojan_Croatia_II_1
{
strings:
	$a0 = { cd1a81fa12027503e99500bf0001beca0003f5a5a4b8ad4bcd213ddcac744cb82135cd213e8c8685013e899e83 }


condition:
	$a0
}