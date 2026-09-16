rule Win_Trojan_Kherson_1
{
strings:
	$a0 = { 9a3a33eab7ea6f6361376290a66525363fe2a063d521ac403b391337f1f1313362676361e2b361d8 }


condition:
	$a0
}