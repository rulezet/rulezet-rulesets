rule Win_Trojan_W_368
{
strings:
	$a0 = { aa4feb619e452a509e4528ce0772e222 }


condition:
	$a0
}