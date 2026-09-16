rule Win_Trojan_Holo_2
{
strings:
	$a0 = { 4d75c35683ee0aad25dfdf3d4942 }


condition:
	$a0
}