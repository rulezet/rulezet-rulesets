rule Win_Trojan_Sadist_2
{
strings:
	$a0 = { 0e9a052bca2e8b1e2600b440cd21 }


condition:
	$a0
}