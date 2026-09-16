rule Win_Trojan_Mnemonix_4
{
strings:
	$a0 = { 21b9ca01bbee013402e6212e8137b0c743433402e621e2ef }


condition:
	$a0
}