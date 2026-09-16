rule Win_Trojan_Kalaha_1
{
strings:
	$a0 = { 0475064646e2f5eb29b82135cd21 }


condition:
	$a0
}