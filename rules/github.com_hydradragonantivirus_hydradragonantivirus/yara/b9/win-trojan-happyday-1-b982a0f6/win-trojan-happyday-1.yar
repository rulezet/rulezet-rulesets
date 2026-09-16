rule Win_Trojan_HappyDay_1
{
strings:
	$a0 = { b8070ecd10b8000fcd10 }


condition:
	$a0
}