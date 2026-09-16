rule Win_Trojan_Violator_10
{
strings:
	$a0 = { 03037407c3cd21c3cd13c3cd26c3 }


condition:
	$a0
}