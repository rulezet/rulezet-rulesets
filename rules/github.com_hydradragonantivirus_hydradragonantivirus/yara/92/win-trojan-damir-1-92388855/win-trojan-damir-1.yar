rule Win_Trojan_Damir_1
{
strings:
	$a0 = { 5d83ed13908bf583c60e908a148a64018bf583c637908bfeb93f0390ac2ac402e2aae2f8 }


condition:
	$a0
}