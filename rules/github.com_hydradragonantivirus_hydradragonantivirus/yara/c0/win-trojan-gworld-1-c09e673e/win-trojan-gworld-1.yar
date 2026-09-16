rule Win_Trojan_GWorld_1
{
strings:
	$a0 = { 0e1f57c33d75357504b84444cf80fc4b7403e984 }


condition:
	$a0
}