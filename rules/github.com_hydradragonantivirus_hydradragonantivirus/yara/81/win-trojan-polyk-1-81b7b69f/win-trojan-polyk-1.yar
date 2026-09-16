rule Win_Trojan_Polyk_1
{
strings:
	$a0 = { 60e8000000005d83ed0655fc81ec640200008bf58bfcb963020000f3a48bec8d4524ffe0[0-50]d9aae2f1 }


condition:
	$a0
}