rule Win_Trojan_Yayih_1
{
strings:
	$a0 = { 91d416d9d09621cb66d83a4024e78e76 }


condition:
	$a0
}