rule Win_Trojan_VGEN_341
{
strings:
	$a0 = { 9c57ada8b9e2a0cea442e7cb04027c07686988ebbb8d6aef807ae9935399c4c44c4a2258825752bf73e1244eab }


condition:
	$a0
}