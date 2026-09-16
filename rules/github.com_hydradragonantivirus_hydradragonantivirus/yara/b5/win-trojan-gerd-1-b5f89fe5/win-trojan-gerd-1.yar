rule Win_Trojan_GERD_1
{
strings:
	$a0 = { 1e9005ba9205b91e0390cd21b43e8b1e9005cd21c7 }


condition:
	$a0
}