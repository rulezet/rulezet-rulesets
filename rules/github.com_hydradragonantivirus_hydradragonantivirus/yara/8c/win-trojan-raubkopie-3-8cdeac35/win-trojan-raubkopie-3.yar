rule Win_Trojan_Raubkopie_3
{
strings:
	$a0 = { 8b1e0a01ad33c3abe2fa075b9dc3 }


condition:
	$a0
}